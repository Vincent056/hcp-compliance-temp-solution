# Design: per-cluster CEL selection + fleet scaling

**Docs:** [README](README.md) · [Runbook](RUNBOOK.md) · [Coverage](COVERAGE.md) · [Design](DESIGN.md) · [Validation](VALIDATION.md) · [Rule Matrix](RULE_COVERAGE_MATRIX.md) · [Background: Scan Mechanics](docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md) · [Background: Strategy](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) · [Background: First Validation](docs-background/HCP_SCAN_VALIDATION_REPORT.md)

## How selection works: native setValues delivery via Rule CRs (updated 2026-08-11)

ALL 15 management-side CEL rules (14 checks + the `hcp-selector-valid` sentinel)
are PER-CLUSTER via native `setValues` delivery. Background: the operator cannot
deliver `setValues` to CEL **CustomRules** - their admission controller compiles
expressions with ONLY the rule's inputs declared, so any variable reference is
rejected (UNDECLARED_REFERENCE), and the fallback tricks all fail (dashed bundle
variable names are not legal CEL identifiers; adding a same-named input to satisfy
validation dies at scan time with cel-go's "overlapping identifier"; the input
fetchers ignore the scanner's variable list). All of this was proven live on stock
v1.9.1.

The pattern that works: ship the rules as directly-created **`Rule` CRs** (kind:
Rule, `scannerType: CEL`) instead of CustomRules. Rule CRs have no admission
controller, so nothing compiles their expressions until scan time - and the
scan-time compile environment is the ONLY one in the operator that declares the
TailoredProfile's `setValues` variables alongside the inputs, binding each scan's
own values. With two dash-free custom Variable CRs (`hypershiftcluster`,
`hypershiftprefix` - dash-free so expressions can reference them as legal
identifiers), the expressions use the selector directly:

```
hcs.items.exists(hc, hc.metadata.name == hypershiftcluster && hc.metadata.namespace == hypershiftprefix)
```

Selection = each TailoredProfile's own `setValues`:

```yaml
setValues:
  - name: hypershiftcluster
    value: <hosted-cluster-name>
  - name: hypershiftprefix
    value: <namespace-prefix>
```

One TailoredProfile instance per hosted cluster, all enabling the SAME 15 Rules -
and because the scanner binds each TP's values per scan, instances run
**CONCURRENTLY** with correct per-cluster results (proven live: two HostedClusters,
one rule set, differing results - validation summary below). No bundle Variable CR is read,
patched, or otherwise involved; the two selector Variables are created once and
their CR values are never used for selection.

Caveats (each deliberate and documented):

- **No admission validation for Rule CRs** - a broken expression surfaces only as
  a scan-time ERROR. Validate every expression change with `celctl verify` before
  applying (the shipped rules carry a 72-case matrix).
- **Both `setValues` entries are REQUIRED in every enabling TailoredProfile** - a
  missing entry means the variable is not declared at scan-time compile, and every
  rule in that scan reports ERROR (loud, and distinct from FAIL).
- **ownerReferences to the ocp4 ProfileBundle** are required on the Rules and
  Variables by the TailoredProfile controller (it verifies UID+name ownership);
  `management/deploy.sh` sets them. UPGRADE-SAFE by construction: the
  profileparser's stale-object sweep after every content re-parse selects
  candidates by the `compliance.openshift.io/profile-bundle` LABEL
  (`deleteObsoleteItems` in the parser), and these objects deliberately do NOT
  carry that label - content-image and operator upgrades cannot delete them
  (verified in code and live). NEVER add `compliance.openshift.io/*` labels to
  these objects; the management label they DO carry
  (`app.kubernetes.io/part-of: hcp-temp-compliance`) is inert to the operator.
  The only lifecycle coupling left is deletion of the ocp4 ProfileBundle object
  itself (kube GC then removes the dependents; a recreated ProfileBundle also
  changes UID) - a rare, manual event; re-run `deploy.sh` afterwards. A dedicated
  owner ProfileBundle would not help: any owner is subject to the same
  delete-GC, and the upgrade sweep already cannot touch these objects.
  Post-upgrade check: `oc get rules -n openshift-compliance -o name | grep -c '/hcp-'`
  should report 15 and `oc get variable hypershiftcluster hypershiftprefix -n
  openshift-compliance` should list both; re-run deploy.sh if not.
- This uses a validation asymmetry in the operator (CustomRules are validated
  against an environment missing the variables; Rules are not validated at all).
  Upstream ask (filed: CMP-4550, target compliance-operator-1.10.0): validate BOTH
  kinds with inputs + declared variables - which would
  let this pattern migrate back to CustomRules unchanged and regain admission
  validation. Until then celctl is the admission gate.
- Every alternative selector design that was evaluated and rejected - including
  the interim variable-as-input and TP-as-input patterns - is listed with its
  evidence and rejection rationale in the validation summary below.
- **Fleet-wide gate variant** (`management/customrules-fleet.yaml`): the original
  fleet semantics as selector-free CustomRules - `.all()` over every
  HostedCluster, CP namespaces derived per cluster from the HostedCluster object
  itself, so nothing is baked and admission validation applies. One scan gates
  the whole fleet (newly onboarded violating clusters trip it); pair with the
  per-cluster instances for attribution. Validated live with a mixed fleet
  (validation summary below).
- The etcd pods input fetches cluster-wide (input specs cannot be templated); on
  very large management clusters consider namespace-baked per-cluster generation
  if pod-list size becomes a concern.

Also unchanged: `management/rbac-hypershift-read.yaml` (one grant for
`hostedclusters`/`nodepools`) and the management cluster's own self-scans
(Layer D).

## Validation summary + alternatives considered (2026-08-10/11)

**The shipped design** (round 4): the 15 management rules are directly-created
`Rule` CRs whose expressions reference the dash-free `hypershiftcluster` /
`hypershiftprefix` Variables; the scanner natively binds each enabling
TailoredProfile's `setValues` per scan (mechanism + caveats above).
Validated on the stock downstream v1.9.1:

- celctl matrix **72/72** - pass/fail bodies, cross-selector isolation (same mock
  data, different selector -> opposite results), ghost-cluster existence guards,
  vacuous NodePool, sentinel cases.
- Single-rule proof first: one hand-made Rule + two TailoredProfiles (values
  `hcp-demo` / `ghost`) scanned concurrently -> **PASS + FAIL** - per-TP delivery
  and concurrency demonstrated in one shot.
- **Two real HostedClusters scanned CONCURRENTLY with one rule set**:
  `hcp-cel-hcp-demo` **9 PASS / 6 FAIL** vs `hcp-cel-hcp-demo2` **10 PASS / 5
  FAIL** - the single differing check (`hcp-oauth-token-maxage`) matches the only
  configuration difference (demo2's `tokenConfig` set). CIS/STIG/High for BOTH
  clusters byte-identical to every baseline (49P/21M/7F / 2P/11M/4F / 43P/23M/7F).
- **Fleet-wide gate** (optional complement, `customrules-fleet.yaml`): 14
  selector-free CustomRules (real admission validation), one scan over the mixed
  fleet -> **8 PASS / 6 FAIL**, `hcp-fleet-oauth-token-maxage` correctly FAILing
  (demo violates although demo2 complies) and the per-HostedCluster namespace
  join ignoring the management cluster's own etcd. celctl 5/5.

**Alternatives evaluated and why they were not chosen** (each validated or
disproven live before rejection):

1. **`setValues` on CustomRules (the natural UX)** - impossible on stock: the
   CustomRule admission controller compiles expressions with inputs-only
   declarations, so any variable reference is rejected (UNDECLARED_REFERENCE,
   dash-free names included); dashed bundle-variable names are not legal CEL
   identifiers anyway; adding a same-named input to satisfy validation dies at
   scan time ("overlapping identifier"); the input fetchers ignore the scanner's
   variable list; and a CEL TailoredProfile carrying `setValues` goes READY and
   scans DONE with the values silently inert (a rule keyed to the setValues
   values FAILed while one keyed to the stored CR values PASSed). Filed as
   CMP-4550 (target compliance-operator-1.10.0); when it lands, the
   shipped rules migrate back to CustomRules unchanged and regain admission
   validation.
2. **Status-forged CustomRules** - mechanically works (patching
   `status.phase: Ready` with matching `observedGeneration` sticks - proven
   live), but it falsifies the controller's recorded verdict; rejected on
   integrity grounds.
3. **Variable-as-input** (round 2: rules fetch the `ocp4-hypershift-*` Variable
   CRs as inputs; select by patching the CR value) - validated 73/73 celctl +
   live three-leg round trip on the real `hcp-demo` (8P/6F -> bogus selector
   13F/1P -> restored 8P/6F), but selection patches a bundle Variable CR and
   allows one active selection at a time - rejected by requirement: never modify
   Variable CRs; selection must live in the TailoredProfile.
4. **TP-as-input** (round 3: rules fetch their enabling TailoredProfile as an
   input and read its `setValues` as data; self-discovery via a `self` input +
   exactly-one guard) - fully working: 133/133 celctl + live legs (pinned and
   arbitrarily-named TPs, ambiguity-guard trip/recover, spec-only etcd round trip
   6P -> ghost 6F -> 6P, JSON multi-select via `parseJSON`, concurrency via
   two-line name-suffixed rule copies). Superseded by native delivery within
   hours: it needed verbose discovery expressions, a guard instead of true
   per-scan context, and rule copies for concurrency - all of which native
   delivery eliminates.
5. **Namespace-baked per-cluster rule copies** (round 1) - correct but requires N
   regenerated rule sets per fleet; retained only as a perf fallback note above.
6. **Fleet-wide `.all()` rules only** (round 1) - no per-cluster attribution;
   retained as the optional gate above, not as the primary.

## Per-hosted-cluster objects (instantiate N times)

| Object | Why per-cluster | Naming convention |
|---|---|---|
| Mgmt TailoredProfiles (`management/tp-cis.yaml`, `tp-stig`, `tp-high`) | The two variables (`ocp4-hypershift-cluster`, `ocp4-hypershift-namespace-prefix`) identify exactly ONE HostedCluster; a scan reads exactly one control-plane namespace | `hypershift-<profile>-<cluster>` (e.g. `hypershift-cis-payments-prod`) |
| CEL TailoredProfile instances (`management/tp-cel.yaml`) | Each instance's `setValues` names ONE cluster; all enable the same 15 shared Rules and scan concurrently (see above) | `hcp-cel-<cluster>` |
| ScanSettingBindings for those TPs | One binding per TP | `hypershift-<profile>-<cluster>` / `hcp-cel-<cluster>` |
| In-hosted install + tailored profiles (`hosted/co-install.yaml`, `hosted/tp.yaml`, SSBs) | The Compliance Operator runs inside EACH hosted cluster | identical manifests per cluster |

Generation is mechanical - every per-cluster manifest differs only in the cluster
name/namespace strings. A 10-line loop over `oc get hostedcluster -A` output (sed on
the name/prefix placeholders) produces the full set; keep the generated manifests in
Git per cluster.

## Distribution and operations at fleet scale

- **In-hosted layer via ACM/MCE policies or GitOps.** MCE auto-imports every hosted
  cluster as a managed cluster; an ACM Policy (or Argo ApplicationSet keyed on the
  hosted-cluster kubeconfig secrets) can push the identical in-hosted bundle
  (Subscription with the worker nodeSelector + PLATFORM env, tailored profiles, SSBs)
  to all hosted clusters and keep it converged as new clusters onboard - avoiding
  N manual installs.
- **Stagger schedules.** N hosted clusters mean N mgmt tailored suites on the
  management cluster; with the shared `default` ScanSetting they all fire at the same
  cron time. Create a few ScanSettings with offset schedules (e.g. one per hour
  bucket) and spread the bindings, so the api-resource-collector load and etcd reads
  on the management cluster do not spike at once.
- **Result slicing.** Scan names embed the cluster name, and every
  ComplianceCheckResult carries the `compliance.openshift.io/scan-name` label -
  `oc get ccr -l compliance.openshift.io/scan-name=hypershift-cis-<cluster>` gives a
  per-cluster report; ACM's governance view aggregates across the fleet.
- **Onboarding checklist for a new hosted cluster:** copy + apply the per-cluster
  mgmt TPs/SSBs (three OpenSCAP + one CEL instance - name + two setValues each);
  let the policy/GitOps engine roll out the in-hosted bundle; the fleet gate
  (`hcp-cel-fleet`) picks the new cluster up automatically; add its scans to the
  schedule bucket with the most headroom.


