# Temporary Compliance Solution for Hosted Control Planes: CIS + STIG + NIST 800-53 High

**Docs:** [README](README.md) · [Runbook](RUNBOOK.md) · [Coverage](COVERAGE.md) · [Design](DESIGN.md) · [Validation](VALIDATION.md) · [Rule Matrix](RULE_COVERAGE_MATRIX.md) · [Background: Scan Mechanics](docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md) · [Background: Strategy](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) · [Background: First Validation](docs-background/HCP_SCAN_VALIDATION_REPORT.md)


**Status: VALIDATED end-to-end four times** (full evidence log: [`VALIDATION.md`](VALIDATION.md)):

- **Round 1** (2026-07-31): 4.21.0 nightly mgmt cluster + `hcp-demo` (none) +
  `hcp-aws` (AWS, 2 workers, in-hosted layer) - baseline results; since torn down.
- **Round 2** (2026-08-10): 4.21.28 GA + real `hcp-demo` - all four profiles
  byte-identical to baseline; celctl matrices for every CEL rule.
- **Round 3** (2026-08-10/11): fresh GA cluster, reorganized manifests, OAuth
  OR rules split server/client, hub+hosted audit-error alert + remediation - all
  proven live on the real guest.
- **Round 4** (2026-08-11): NATIVE per-TP `setValues` delivery via Rule CRs +
  SECOND HostedCluster - two TPs scanned two clusters CONCURRENTLY with one rule
  set (demo 9P/6F vs demo2 10P/5F), fleet gate validated, CIS/STIG/High baselines
  reproduced for BOTH clusters. `hcp-demo` + `hcp-demo2` left running.

Rounds 1-2 were scan-only; rounds 3-4 additionally validated targeted remediations
live (guest audit-error alert, per-client OAuth overrides, demo2 `tokenConfig`) -
each FAIL->fix->PASS transition is recorded in [`VALIDATION.md`](VALIDATION.md).

## Background in 60 seconds

With Hosted Control Planes (HCP, the product form of the HyperShift project), a
cluster's control plane (kube-apiserver, etcd, controllers) does not run inside the
cluster itself - it runs as ordinary pods on a separate **management cluster**, in a
namespace named `<prefix>-<clustername>`. The **hosted cluster** contains only worker
nodes and workloads. A compliance scan can only see the cluster it runs in, so no
single scan can assess a hosted cluster completely: control-plane configuration is
only visible from the management side, in-cluster settings (RBAC, registries,
routes...) only from inside the hosted cluster. This repo provides and live-validates
the combination of scans and custom checks that together cover the CIS, DISA STIG,
and NIST 800-53 High benchmarks for hosted clusters.

## TL;DR

Customers running self-managed Hosted Control Planes can reach near-complete
automated coverage of CIS, STIG, and NIST 800-53 High **today, with no content
changes**, by combining four scan layers (all validated live in this repo):

1. **Mgmt tailored scans** - TailoredProfiles with the two HyperShift variables
   (one set per hosted cluster, per the official procedure:
   [Configuring the hosted control planes management cluster](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#co-hcp-mgmt-config_compliance-operator-scans))
   cover the hosted control-plane configuration.
2. **CEL rules on the mgmt cluster** (shipped as Rule CRs, per-cluster via
   TailoredProfile `setValues` - [`DESIGN.md`](DESIGN.md)) - replace the 6 etcd false-positive
   rules and check the settings whose source of truth is `HostedCluster.spec`
   (FIPS, etcd encryption, audit profile, TLS profile, OAuth token policy, webhook).
3. **In-hosted scans** - CO installed inside each hosted cluster following the
   documented install procedure (note: official in-hosted support currently covers
   node profiles; the platform-profile scans in this layer are enabled by this
   package's tailored profiles) ([Installing the Compliance Operator on Hypershift hosted control planes](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation),
   Technology Preview: Subscription with worker `nodeSelector` + `PLATFORM=HyperShift` env) with tailored profiles that
   disable the control-plane rules; covers all in-cluster checks and node profiles.
4. **Mgmt self-scans + manual attestations** complete the picture.

## Documentation map

- [`RUNBOOK.md`](RUNBOOK.md) — how to launch every scan (management + in-hosted),
  read the results, manage/uninstall the objects, and remediate the standing FAILs.
- [`COVERAGE.md`](COVERAGE.md) — per-benchmark dispositions: what covers each
  CIS/STIG/High rule and the combined coverage numbers.
- [`DESIGN.md`](DESIGN.md) — how per-cluster CEL selection works (native
  `setValues` delivery via Rule CRs), every alternative evaluated and why it was
  rejected, and fleet-scale operations.
- [`VALIDATION.md`](VALIDATION.md) — the full evidence log across all four
  validation rounds, bugs found, and the in-hosted layer results.
- [`RULE_COVERAGE_MATRIX.md`](RULE_COVERAGE_MATRIX.md) — per-rule live results
  from both scan locations for every platform rule.
- `docs-background/` — historical snapshots from the 2026-07-31 round 1:
  [scan mechanics](docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md),
  [strategy & gap analysis](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md),
  [first validation report](docs-background/HCP_SCAN_VALIDATION_REPORT.md).

## Official support boundary (read this before an audit)

Per the OpenShift documentation (Supported compliance profiles): on hosted
control plane MANAGEMENT clusters, only `ocp4-cis` and `ocp4-pci-dss` are
supported; official in-hosted support covers the NODE profiles
(`ocp4-{cis,stig,high}-node`, `rhcos4-*` - ROSA HCP is listed as a supported
platform for them). Mapped onto this package:

| Layer | Support status |
|---|---|
| `hypershift-cis-<cluster>` mgmt scans | **Supported surface** - extends `ocp4-cis` via the documented management-cluster procedure (TailoredProfile + HyperShift variables) |
| In-hosted node scans (`*-node`, `rhcos4-*`) | **Supported surface** for all three benchmarks |
| `hypershift-stig/high-<cluster>` mgmt scans | Temporary: validated 4x, but ocp4-stig/ocp4-high are NOT in the supported set for HCP management clusters - treat as compensating automated evidence |
| In-hosted PLATFORM scans (`hosted-*-tailored`) | Temporary: official in-hosted scope is node profiles only (CMP-4521) |
| CEL rules (per-cluster + fleet) | Temporary: user-defined checks; provenance per rule in the matrix |

For the assessor: compliance is determined by an authorized auditor (QSA/JAB),
not by profile support status - this package produces evidence with rule-by-rule
provenance ([`RULE_COVERAGE_MATRIX.md`](RULE_COVERAGE_MATRIX.md)), clearly
separating supported-profile results from temporary-layer results. Roadmap to
fully supported: an RFE for official `ocp4-stig`/`ocp4-high` on HCP management
clusters (in preparation), CMP-4550 for CEL selector support, and
CMP-4520/21/23/24 for the individual content gaps.

## Coverage / gap metrics (platform profiles, live-validated)

| | CIS (94 rules) | STIG (48 rules) | High (134 rules) |
|---|---|---|---|
| Mgmt scan, HyperShift-aware (truthful hosted-CP results) | 47 | 6 | 57 |
| CEL CustomRules (replacements + gap rules) | 10 | 6 | 15 |
| In-hosted scan (in-cluster half) | 13 | 20 | ~29 |
| Correctly NOT-APPLICABLE (auto-suppressed, SDN-gated, or architectural) | 7 | 4 | 12 |
| Manual attestation (attest vs hosted cluster) | 21 | 11 | 25 |
| **No automated equivalent (record in the System Security Plan)** | **2** | **1** | **3** |
| Node-dimension rules (in-hosted node profiles) | 103 | 121 | 123 |

Bottom line: with all layers deployed, **every automated platform rule has exactly
one authoritative source except the two `no-unsupported-config-overrides` rules and
`cluster-version-operator-verify-integrity`** (architecturally N/A on HCP - record in
the SSP; the CVO runs no signature verification on HyperShift, see the findings table). The weakest single layer is the
STIG mgmt scan (only 6 aware rules); the in-hosted + CEL layers close most of it.

## Findings discovered and filed during validation

| Jira | Finding |
|---|---|
| CMP-4520 (Bug, Major) | 6 etcd rules false-FAIL on HCP - etcd config moved to `ETCD_*` env vars |
| CMP-4521 (Bug, Major) | `ocp4-on-hypershift-hosted` CPE never fires (initContainer vs `.spec.containers` OVAL mismatch), so control-plane rules false-FAIL if platform profiles are run inside a hosted cluster. Current official in-hosted support covers node profiles only, so no supported flow hits this — but this package's in-hosted tailored profiles (`hosted/tp.yaml`) work around it and make in-hosted platform scans usable. |
| CMP-4522 (Bug, Major) | CSV master `nodeSelector` blocks scheduling on hosted clusters — the Subscription override is ALREADY the documented install procedure ([Installing the Compliance Operator on Hypershift hosted control planes](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation), Technology Preview); ticket to be closed/rescoped |
| CMP-4523 (Story) | Collector SA lacks `nodepools` RBAC for CEL inputs |
| CMP-4524 (Story) | Extend HyperShift awareness to the HostedCluster-derivable rules |
| CMP-TBD (Bug) | `cluster_version_operator_verify_integrity` is a structural false positive in hosted clusters: the CVO performs **no** release-image signature verification on HyperShift (confirmed by OTA/HCP engineering; the CPO deploys the CVO with a pre-extracted `PAYLOAD_OVERRIDE` payload and a matching `RELEASE_IMAGE`, so the verification path is never entered), leaving `.status.history[].verified` false forever. The rule's jq filter drops the newest history entry, so a never-upgraded hosted cluster passes vacuously (what round 1 saw) and every upgraded one FAILs permanently. Content fix: gate the rule `not ocp4-on-hypershift-hosted` (blocked on CMP-4521). Platform fix: an RFE against OTA-951 / RFE-8928. Temp solution here: disabled in `hosted/tp.yaml` (STIG + High) with the management cluster as the compensating control. |
| CMP-4550 (Bug, Major, target 1.10.0) | TailoredProfile `setValues` silently ignored by CEL rules + validation asymmetry - the fix migrates this repo's Rule-CR selector back to admission-validated CustomRules ([`DESIGN.md`](DESIGN.md)) |

Full per-rule detail: [`RULE_COVERAGE_MATRIX.md`](RULE_COVERAGE_MATRIX.md). Multi-cluster fleets: [`DESIGN.md`](DESIGN.md).

## Glossary (read this if any term above is unfamiliar)

| Term | Meaning |
|---|---|
| Management cluster | The OpenShift cluster that runs hosted control planes as pods |
| Hosted cluster | The tenant cluster: worker nodes + workloads, no control-plane pods |
| CP / control-plane namespace | `<prefix>-<name>` namespace on the management cluster holding one hosted control plane |
| CO | Compliance Operator - runs the scans, from either cluster |
| MCE | multicluster engine operator - installs/manages HyperShift (`HostedCluster` API) |
| TailoredProfile | CO object that customizes a profile: set variables, enable/disable rules |
| ScanSettingBinding (SSB) | CO object that binds profiles to scan settings and starts scanning |
| ComplianceCheckResult | Per-rule scan result object: PASS / FAIL / MANUAL / NOT-APPLICABLE |
| CEL rule (CustomRule / Rule CR) | User-defined CO check written in Common Expression Language against live API objects |
| HyperShift-aware (dual-path) rule | Content rule whose fetch path switches to the hosted CP namespace when the HyperShift variables are set |
| Wrong-target rule | Rule that, in a management scan, reads the management cluster's own config and so reports on the wrong cluster |
| CPE / platform | The content's applicability mechanism - decides which rules run on which cluster type |
| SSP | System Security Plan - the accreditation document where non-automatable items are recorded |
| Technology Preview | Red Hat support level: early access, not covered by production SLAs |

---

This package delivers the best currently-achievable automated coverage of the CIS,
DISA STIG, and NIST 800-53 High benchmarks for a hosted cluster **without any
ComplianceAsCode content changes**, using only supported Compliance Operator
primitives: TailoredProfiles, `disableRules`, and CEL CustomRules.

Manifests (all applied and validated live), organized by WHERE they are applied:

| File | Applied on | Purpose |
|---|---|---|
| `management/customrules.yaml` | management cluster | 2 dash-free selector Variables + 15 CEL rules as directly-created `Rule` CRs, PER-CLUSTER via `setValues` in each enabling TailoredProfile (NATIVE delivery, [`DESIGN.md`](DESIGN.md)): 6 etcd env-var checks (replace false positives) + 8 HostedCluster/NodePool gap rules + the `hcp-selector-valid` sentinel |
| `management/deploy.sh` | management cluster | Applies customrules.yaml and sets the ownerReferences (to the ocp4 ProfileBundle) that the TailoredProfile controller requires on Rules and Variables |
| `management/customrules-fleet.yaml` + `tp-cel-fleet.yaml` | management cluster | OPTIONAL fleet-wide gate: 14 CustomRules (admission-validated; selector-free) evaluating EVERY HostedCluster in one scan - any violating cluster FAILs the gate; CP namespaces derived from the HostedCluster objects (no prefix baked; prefix-scoped variants would be customrules-fleet-<prefix>.yaml) |
| `management/rbac-hypershift-read.yaml` | management cluster | Read grant on `hostedclusters`/`nodepools` for the `api-resource-collector` SA (required for the CEL inputs; without it the NodePool rule returns ERROR — reproduced live) |
| `management/tp-cel.yaml` | management cluster | Per-hosted-cluster TailoredProfile instance (the `hcp-demo` one; copy per cluster) binding the 15 Rules; the target is this TP's OWN `setValues`, delivered natively to the expressions — multiple instances scan different clusters CONCURRENTLY ([`DESIGN.md`](DESIGN.md)) |
| `management/tp-cis.yaml` / `tp-stig.yaml` / `tp-high.yaml` | management cluster | Per-profile TailoredProfiles: hypershift `setValues` + 10 / 27 / 51 `disableRules` |
| `management/ssb.yaml` | management cluster | ScanSettingBindings for all four management scans |
| `hosted/co-install.yaml` | each hosted cluster | CO install with the documented Subscription overrides (worker `nodeSelector` + `PLATFORM=HyperShift`) |
| `hosted/customrules.yaml` | each hosted cluster | 3 CEL CustomRules: the two CLIENT halves of the split OAuth OR rules (`hcp-oauthclient-token-maxage`, `hcp-oauthclient-inactivity-timeout`) + the hub+hosted `hcp-audit-error-alert-exists` |
| `hosted/tp.yaml` | each hosted cluster | `hosted-cis/stig/high-tailored`: control-plane rules disabled (46/6/56) incl. the split OAuth OR rules |
| `hosted/tp-cel.yaml` + `hosted/ssb.yaml` | each hosted cluster | CEL TailoredProfile for the 3 in-hosted CustomRules + ScanSettingBindings |
| `hosted/remediation-audit-errors.yaml` | each hosted cluster | Remediation: the audit-error alert missing from 4.21 guests ([`RUNBOOK.md`](RUNBOOK.md) remediations) |
| `hostedcluster.yaml` | management cluster | The none-platform HostedCluster used for validation (parameterized: release image + base domain) |

Per-hosted-cluster values to substitute: the cluster name / namespace prefix in the
TailoredProfiles' `setValues`. The OpenSCAP TPs use the bundle variables
(`ocp4-hypershift-*`); the CEL TailoredProfile uses the dash-free
`hypershiftcluster` / `hypershiftprefix` Variables so the scanner can deliver each
TP's values natively into the expressions ([`DESIGN.md`](DESIGN.md)). No bundle Variable CR is
ever modified.

---
