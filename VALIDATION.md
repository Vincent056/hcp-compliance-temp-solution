# Validation evidence log (rounds 1-4)

**Docs:** [README](README.md) · [Runbook](RUNBOOK.md) · [Coverage](COVERAGE.md) · [Design](DESIGN.md) · [Validation](VALIDATION.md) · [Rule Matrix](RULE_COVERAGE_MATRIX.md) · [Background: Scan Mechanics](docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md) · [Background: Strategy](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) · [Background: First Validation](docs-background/HCP_SCAN_VALIDATION_REPORT.md)

## Round 1: live validation results (2026-07-31; reproduced identically in rounds 2-4 below)

| Scan | Results | Verdict on mechanism |
|---|---|---|
| `hypershift-cis-hcp-demo` (rescan with disables) | 77 checks: 49 PASS / 21 MANUAL / **7 FAIL** (was 17 FAIL before) | All 10 disabled rules absent; every remaining FAIL is a genuine hosted-cluster finding |
| `hypershift-stig-hcp-demo` | 17 checks: 2 PASS / 11 MANUAL / 4 FAIL | Exactly the predicted shape (48 − 27 disabled − 4 auto-N/A); all 6 automated results come from the HyperShift-aware rules reading the HostedCluster |
| `hypershift-high-hcp-demo` | 73 checks: 43 PASS / 23 MANUAL / 7 FAIL | Zero etcd false positives, zero wrong-target FAILs; all 7 FAILs genuine |
| `hcp-cel-workarounds` | 14 checks: **8 PASS / 6 FAIL** | 14/14 match ground truth (see below) |

CEL rule-by-rule vs ground truth:

| CustomRule | Result | Ground truth |
|---|---|---|
| `hcp-etcd-cert-file`, `-key-file`, `-client-cert-auth`, `-peer-cert-file`, `-peer-key-file`, `-peer-client-cert-auth` | PASS x6 | Hosted etcd TLS is fully configured via `ETCD_*` env vars — the six OpenSCAP rules FAILed on the same pods (they only inspect args). Workaround proven. |
| `hcp-api-tls-security-profile` | PASS | No `tlsSecurityProfile` set -> Intermediate default, compliant |
| `hcp-nodepool-config` | PASS | Zero NodePools (vacuous; ERROR before the RBAC grant — apply `rbac-hypershift-read.yaml`) |
| `hcp-fips-enabled` | FAIL | `spec.fips` unset — true finding |
| `hcp-etcd-secret-encryption` | FAIL | `spec.secretEncryption` unset — true finding |
| `hcp-audit-profile` | FAIL | No audit profile configured — true finding |
| `hcp-oauth-token-maxage`, `hcp-oauth-inactivity-timeout` | FAIL | No OAuth tokenConfig — true findings |
| `hcp-audit-webhook` | FAIL | No `spec.auditWebhook` — true finding |

The remaining scan FAILs (CIS 7 / High 7 / STIG 4) are all accurate statements about
`hcp-demo`: audit-log maxbackup=1/maxsize=10 in the hosted `kas-config` (below CIS
thresholds), no etcd secret encryption, no IdP, no OAuth templates, no audit webhook.
NON-COMPLIANT is the correct verdict for an unhardened cluster.

## Bugs and sharp edges found during validation

1. **etcd rules false-positive on HCP 4.21** (`etcd-cert-file` + 5 siblings): hosted
   etcd is configured via `ETCD_*` env vars, the content only inspects pod args.
   This package disables the six rules and replaces them 1:1 with CEL; the upstream
   content fix is tracked as CMP-4520 (evidence in
   [`HCP_SCAN_VALIDATION_REPORT.md`](docs-background/HCP_SCAN_VALIDATION_REPORT.md) section 5).
2. **RBAC**: `api-resource-collector` can read `hostedclusters` out of the box (they
   aggregate into cluster-reader) but NOT `nodepools` — the NodePool CEL rule
   returned ERROR with a forbidden message until `rbac-hypershift-read.yaml` was
   applied. Reproduced and fixed live.
3. **TailoredProfile requires `spec.description`** when creating STIG/High TPs — the
   apply fails without it.
4. CustomRule expressions are static — no substitution in the expression text —
   which originally forced baking the CP namespace (`clusters-hcp-demo`) into the
   etcd rules. Superseded: the rules now ship as directly-created Rule CRs whose
   expressions reference the dash-free selector Variables, and the scanner
   delivers each TailoredProfile's `setValues` natively ([`DESIGN.md`](DESIGN.md)).
5. CI-environment HostedCluster hints (not compliance-related):
   `controllerAvailabilityPolicy: SingleReplica` on <3-AZ management clusters,
   `olmCatalogPlacement: guest` for nightly releases; both immutable.

## In-hosted scan layer (round 1, validated on hcp-aws)

An AWS-platform HostedCluster `hcp-aws` (4.20.32 GA, 2× m5.xlarge workers, created via
MCE `hcp` CLI with `--control-plane-availability-policy SingleReplica`) was used to
validate the "install the Compliance Operator inside each hosted cluster" layer.

New manifests in this directory:

| File | Purpose |
|---|---|
| `hosted/co-install.yaml` | OLM install of CO v1.9.1 inside the hosted cluster, matching the official documented procedure ([Installing the Compliance Operator on Hypershift hosted control planes](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation), Technology Preview): `spec.config.env` `PLATFORM=HyperShift` + `spec.config.nodeSelector: {node-role.kubernetes.io/worker: ""}`. Without the overrides the operator pod stays Pending (CSV pins to masters; hosted clusters have none) — our validation independently confirmed the documented settings are load-bearing. |
| `hosted/tp.yaml` | `hosted-cis-tailored` / `hosted-stig-tailored` / `hosted-high-tailored` — disable the control-plane rules (46 / 7 / 57, incl. the split OAuth OR rules and `cluster-version-operator-verify-integrity`) inside the hosted cluster |
| `hosted/customrules.yaml`, `hosted/tp-cel.yaml` | the 3 in-hosted CEL rules (OAuth client halves + audit-error alert) and their TailoredProfile |
| `hosted/ssb.yaml` | tailored platform + CEL bindings |

### Finding: the ocp4-on-hypershift-hosted CPE never fires (why the tailored profiles exist)

With plain `ocp4-cis` inside the hosted cluster, 11+ control-plane rules RAN and
false-FAILed (reading `openshift-kube-apiserver` etc. namespaces that do not exist).
Root cause, confirmed in source: the operator passes `--platform=HyperShift` to the
`api-resource-collector`, which is an **initContainer** of the platform scan pod
(`pkg/controller/compliancescan/scan.go`, `addScannerInitContainer`), while the
content's CPE check (`shared/applicability/oval/installed_app_is_ocp4.xml`,
`object_hypershift_hosted`) inspects `.spec.containers[:].command[:]` only —
initContainers are never examined. Same code on current master. Fix options (not
applied per current plan): move the arg to a regular container, or extend the OVAL to
initContainers. Until fixed, the tailored profiles replicate the CPE gating manually.

### In-hosted validation results (all six + three tailored scans DONE)

| Scan | Result | Notes |
|---|---|---|
| `ocp4-cis` (untailored) | 22 PASS / 21 MANUAL / 46 FAIL | demonstrates the CPE bug: ~38 false CP FAILs |
| `hosted-cis-tailored` | 14 PASS / 21 MANUAL / 8 FAIL | CP rules absent; remaining FAILs genuine (kubeadmin present, registries unset, ingress ciphers default, netpol missing) |
| `hosted-stig-tailored` | 14 PASS / 11 MANUAL / 19 FAIL | banner/MOTD/logout-url/project-template FAILs = real unhardened-cluster findings |
| `hosted-high-tailored` | 28 PASS / 23 MANUAL / 24 FAIL | same pattern |
| `ocp4-cis-node-worker` | 57 PASS — **COMPLIANT** | 4.20 workers pass CIS node checks out of the box |
| `ocp4-stig-node-worker` | 2 PASS / 1 FAIL | kubelet STIG |
| `rhcos4-stig-worker` | 17 PASS / 1 MANUAL / 98 FAIL | OS-level STIG on unhardened RHCOS — the node-hardening workload that NodePool config must address |
| `ocp4-high-node-worker` | 61 PASS / 3 MANUAL / 1 FAIL | NIST High kubelet/node checks |
| `rhcos4-high-worker` | 40 PASS / 4 MANUAL / 194 FAIL | NIST High OS baseline on unhardened RHCOS — same NodePool hardening backlog |

Gap-rule recovery verified rule-by-rule: every rule the coverage matrix assigns to
"Hosted scan" produced a genuine in-hosted result — `kubeadmin-removed` FAIL (true:
fresh cluster), `ocp-allowed-registries` FAIL, `ingress-controller-tls-cipher-suites`
FAIL, `api-server-anonymous-auth` PASS, `scc-limit-container-allowed-capabilities`
PASS, `api-server-profiling-protected-by-rbac` PASS,
`configure-network-policies-namespaces` FAIL, STIG `classification-banner` /
`openshift-motd-exists` / `oauth-logout-url-set` FAIL, `image-pruner-active` PASS.

[`RULE_COVERAGE_MATRIX.md`](RULE_COVERAGE_MATRIX.md) now carries live results from BOTH scan locations for every
platform rule of all three profiles.

### Environment notes for reproduction

- MCE OIDC S3 secret (`hypershift-operator-oidc-provider-s3-credentials` in
  `local-cluster` ns) must exist before creating AWS HostedClusters; the hcp CLI needs
  `AWS_REGION` exported for its STS AssumeRole call.
- `ValidAWSIdentityProvider=False WebIdentityErr` shortly after creation is IAM OIDC
  eventual consistency; it resolved itself within ~5 minutes.
- Both ROUND-1 hosted clusters (`hcp-demo`, `hcp-aws`) were kept running for post-scan
  inspection and have since been torn down (validation complete; results preserved
  in these docs).

## Consolidated findings list (all validated live)

1. etcd rules false-positive on HCP 4.21+ (env-var config) — CEL replacement shipped here. Filed: CMP-4520.
2. `oauth_or_oauthclient_inactivity_timeout` and siblings not HyperShift-aware — CEL gap rules shipped here. Filed: CMP-4524.
3. Downstream CSV master `nodeSelector` blocks OLM install on hosted clusters — the Subscription override (worker nodeSelector + PLATFORM env) is the officially documented install procedure ([Installing the Compliance Operator on Hypershift hosted control planes](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation), Technology Preview); validated live. CMP-4522 filed before finding the docs — to be closed or rescoped to 'tolerate masterless topologies natively'.
4. `ocp4-on-hypershift-hosted` CPE unreachable (initContainer vs `.spec.containers` OVAL mismatch) — affects platform profiles run in-hosted, which is beyond the current node-profiles-only support scope; this package's in-hosted tailored profiles are the workaround that makes those scans usable. Filed: CMP-4521.
5. `cluster_version_operator_verify_integrity` is a structural false positive in hosted
   clusters — the CVO performs NO release-image signature verification on HyperShift
   (confirmed by OTA/HCP engineering: the CPO deploys the CVO with a pre-extracted
   `PAYLOAD_OVERRIDE` payload and a `RELEASE_IMAGE` matching the desired image, so
   `RetrievePayload` returns `Local: true` and never reaches the verification path).
   `.status.history[].verified` is therefore false on every entry, permanently.
   Round 1 recorded this rule as PASS in-hosted, which was a **vacuous pass**: the
   rule's jq filter is `[.status.history[0:-1]|.[]|.verified]`, which drops the newest
   entry, and `hcp-aws` was a fresh never-upgraded cluster with exactly one history
   entry — the filtered set was empty, so `check_existence: any_exist` passed with
   nothing to check. Any hosted cluster that has been upgraded once has >=2 entries,
   all `verified: false`, and FAILs permanently (history is append-only/immutable).
   Now disabled in `hosted/tp.yaml` (STIG + High; CIS does not carry the rule).
   Compensating control for the SSP: the management cluster's own CVO verifies its
   releases, and the HyperShift Operator / CPO control which release image the hosted
   control plane runs. Content fix would be to gate the rule
   `not ocp4-on-hypershift-hosted` (blocked on CMP-4521); platform fix is an RFE
   against OTA-951 / RFE-8928.
   The CONTROL is still automatable: `cluster_version_operator_verify_integrity` is
   only one member of a rule set. CNTR-OS-000740 (STIG) and SA-10(1) (NIST High) also
   select `cluster_version_operator_exists` (PASSes in-hosted) and, for SA-10(1),
   `reject_unsigned_images_by_default`; STIG carries the same requirement separately as
   CNTR-OS-000360 ("OpenShift must verify container images"). That rule is
   `platform: ocp4-node`, is selected in `ocp4-stig-node` and `ocp4-high-node` (the
   SUPPORTED in-hosted surface), and checks `/etc/containers/policy.json` for
   `"default": [{"type": "reject"}]` - runtime-level signature enforcement on every
   image pull, which is what the control text actually asks for. Default RHCOS ships
   `insecureAcceptAnything`, so the rule FAILs until remediated. Remediation on HCP
   goes through `NodePool.spec.config` (hosted clusters run no MCO). NOTE: the
   MachineConfig in the upstream STIG fixtext sets the default to `reject` but exempts
   `quay.io/openshift-release-dev` with `insecureAcceptAnything`, so it passes the rule
   without enforcing RELEASE-image signatures - add a `signedBy` entry plus the
   matching `registries.d` signature store for the release registry (or the local
   mirror) to meet the intent of CNTR-OS-000740.
6. `api-resource-collector` lacks RBAC for `nodepools` (has `hostedclusters` via cluster-reader aggregation) — `rbac-hypershift-read.yaml` required for the NodePool CEL rule. Filed: CMP-4523.


## Rounds 2-4: revalidation evidence (2026-08-10/11)

The management-side package was re-run against a REAL HostedCluster (`hcp-demo`,
none-platform) on a 4.21.28 GA management cluster with CO v1.9.1:

- `hypershift-cis-hcp-demo`: **49 PASS / 21 MANUAL / 7 FAIL — byte-identical to the
  original nightly-cluster baseline**, same FAIL set, all 10 disabled rules absent,
  `kubeadmin-removed` auto-N/A, `audit-log-forwarding-webhook` present (mgmt CPE).
- `hcp-cel-workarounds`: **14/14 identical** — six etcd env-var rules PASS
  (CMP-4520 reproduces on GA), six true findings FAIL, TLS profile + NodePool PASS.

New that round: a single OR-semantics CustomRule for
`oauth_or_oauthclient_token_maxage` (celctl 7/7 + live both directions) —
superseded in round 3 by the SPLIT server/client rules (see Round 3 below), because the
OR spans two clusters on HCP and the guest's `oauths/cluster` is not the server
truth. The split pair replaces it: `hcp-oauth-*` (mgmt, server half) +
`hcp-oauthclient-*` (in-hosted, client half).

### Round 2 results: all profiles revalidated on GA (2026-08-10)

| Tailored scan vs real hcp-demo | Result | vs baseline |
|---|---|---|
| CIS (with disables) | 49 PASS / 21 MANUAL / 7 FAIL | identical counts AND FAIL set |
| STIG (27 disables) | 2 PASS / 11 MANUAL / 4 FAIL | identical counts AND FAIL set |
| High (51 disables) | 43 PASS / 23 MANUAL / 7 FAIL | identical counts AND FAIL set |
| PCI-DSS (no disables - first-ever run of the 2nd supported profile) | 67 PASS / 22 MANUAL / 22 FAIL | matches the guide's predicted dispositions rule-by-rule |

PCI details: the 6 etcd false-positives appear (CMP-4520 confirmed in PCI), the 9
wrong-target FAILs match the guide's PCI list exactly, all 5 auto-N/A rules
(incl. compound-platform `file-integrity-*`) are absent, and aware rules PASS from
hosted-CP data (`api-server-tls-cipher-suites`, `tls-version-check-apiserver`,
`configure-network-policies-hypershift-hosted`). Note: the built profile carries
111 rules vs the 67 counted from the controls files - rule COUNTS are
content-version-dependent; the disposition CLASSES (aware / wrong-target /
auto-N/A) are what the analysis guarantees, and all sampled rules matched.

Additionally: every CEL rule of that round's set was unit-validated through celctl
(the operator's scanner engine) with fixture matrices generated from the deployed
expressions — 73/73 for the 14 management rules, 7/7 for the OAuth rule. (The
current native rule set carries its own 72-case matrix - [`DESIGN.md`](DESIGN.md).)

### Round 3: manifest reorg, split OAuth OR rules, hub+hosted audit alert (2026-08-10/11)

Environment: fresh 4.21.28 GA management cluster (`ci-ln-4xx7i82`), CO v1.9.1 +
MCE 2.17.1 installed from scratch, new none-platform `hcp-demo` (later joined by
`hcp-demo2`; both left running). Everything deployed from this repo's reorganized
`management/` and `hosted/` manifests exactly as the Runbook describes; the
malformed round-1 `tp-cis` manifest (an `oc get` dump) was rebuilt clean. CIS
49P/21M/7F, STIG 2/11/4, High 43/23/7 - identical FAIL sets, third reproduction.

- **OAuth OR rules split server/client** - live-proven that the guest's
  `oauths/cluster` is NOT reconciled from `HostedCluster.spec.configuration.oauth`
  (patching `tokenConfig` restarted the CP-side `oauth-openshift` deployment while
  the guest object stayed `{}`), so the original in-hosted OR rules mis-evaluate
  their server half and are now disabled in `hosted/tp.yaml`. The split pair
  covers the OR: `hcp-oauth-*` (mgmt, HostedCluster.spec) + `hcp-oauthclient-*`
  (in-hosted). Client-half evidence on the real guest: FAIL with stock
  OAuthClients -> per-client overrides applied (they persist; not reconciled
  away) -> PASS; celctl 8/8. The demo guest now shows the OR resolution: server
  half FAIL + client half PASS = requirement met.
- **`audit-error-alert-exists` adapted for hub + hosted** - 4.21 guests ship NO
  audit-error alert (zero matching PrometheusRules; the namespace holds only
  `api-usage`/`podsecurity`), and the hub's shipped alert filters on
  `apiserver=~".+-apiserver"`, which 4.21 hosted apiserver metrics lack (4.22
  adds it). New `hcp-audit-error-alert-exists` accepts labeled and label-free
  expressions (mirroring the original OVAL pattern), evaluating correctly on both
  hub and hosted clusters; celctl 5/5. Remediation
  `hosted/remediation-audit-errors.yaml` validated end-to-end on the real guest:
  FAIL -> apply -> PASS.
- In-hosted CEL rules were validated against the real guest API with `celctl
  live` (the none-platform demos have no workers; the in-hosted CO deployment
  itself was exercised in round 1 on `hcp-aws`).

### Round 4: native delivery + two-HostedCluster concurrent validation (2026-08-11)

The round-4 evidence (celctl 72/72, single-rule concurrency proof, two clusters
scanned concurrently with one rule set - demo 9P/6F vs demo2 10P/5F, both
clusters' CIS/STIG/High baselines, fleet gate 8P/6F) lives with the design it
validates: [`DESIGN.md`](DESIGN.md), "Validation summary + alternatives
considered". A final end-to-end pass additionally followed
[`RUNBOOK.md`](RUNBOOK.md) verbatim from a wiped cluster (uninstall one-liner ->
deploy.sh -> per-cluster TP copies -> SSBs -> fleet) and reproduced every
expected tally AND exact FAIL set across all nine scans, plus the guest-side
checks (remediated demo guest PASS x3, stock demo2 guest FAIL x3).
