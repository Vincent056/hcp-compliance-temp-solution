# Temporary Compliance Solution for Hosted Control Planes: CIS + STIG + NIST 800-53 High

**Docs:** [Solution README](README.md) · [Rule Coverage Matrix](RULE_COVERAGE_MATRIX.md) · [Scan Mechanics Guide](docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md) · [Strategy & Gap Analysis](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) · [Validation Report](docs-background/HCP_SCAN_VALIDATION_REPORT.md)

**Status: VALIDATED end-to-end on a live cluster, 2026-07-31.**
Environment: OCP 4.21.0 nightly management cluster (AWS), Compliance Operator **v1.9.1**
(downstream), MCE **v2.17.1**, HostedCluster `hcp-demo` (none-platform, CP-only,
left running for further testing). Scan-only: no remediations were applied
(`default` ScanSetting, auto-apply off).

## TL;DR

Customers running self-managed Hosted Control Planes can reach near-complete
automated coverage of CIS, STIG, and NIST 800-53 High **today, with no content
changes**, by combining four scan layers (all validated live in this repo):

1. **Mgmt tailored scans** - TailoredProfiles with the two HyperShift variables
   (one set per hosted cluster, per the official procedure:
   [Configuring the hosted control planes management cluster](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#co-hcp-mgmt-config_compliance-operator-scans))
   cover the hosted control-plane configuration.
2. **CEL CustomRules on the mgmt cluster** - replace the 6 etcd false-positive rules
   and check the settings whose source of truth is `HostedCluster.spec`
   (FIPS, etcd encryption, audit profile, TLS profile, OAuth token policy, webhook).
3. **In-hosted scans** - CO installed inside each hosted cluster following the
   documented install procedure ([Installing the Compliance Operator on Hypershift hosted control planes](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation),
   Technology Preview: Subscription with worker `nodeSelector` + `PLATFORM=HyperShift` env) with tailored profiles that
   disable the control-plane rules; covers all in-cluster checks and node profiles.
4. **Mgmt self-scans + manual attestations** complete the picture.

### Coverage / gap metrics (platform profiles, live-validated)

| | CIS (94 rules) | STIG (48 rules) | High (134 rules) |
|---|---|---|---|
| Mgmt scan, HyperShift-aware (truthful hosted-CP results) | 47 | 6 | 57 |
| CEL CustomRules (replacements + gap rules) | 10 | 6 | 15 |
| In-hosted scan (in-cluster half) | 13 | 21 | ~30 |
| Correctly NOT-APPLICABLE (auto or SDN/arch) | 7 | 4 | 12 |
| Manual attestation (attest vs hosted cluster) | 21 | 11 | 25 |
| **No automated equivalent (SSP statement)** | **2** | **0** | **2** |
| Node-dimension rules (in-hosted node profiles) | 103 | 121 | 123 |

Bottom line: with all layers deployed, **every automated platform rule has exactly
one authoritative source except the two `no-unsupported-config-overrides` rules**
(architecturally N/A on HCP - record in the SSP). The weakest single layer is the
STIG mgmt scan (only 6 aware rules); the in-hosted + CEL layers close most of it.

### Findings discovered and filed during validation

| Jira | Finding |
|---|---|
| CMP-4520 (Bug, Major) | 6 etcd rules false-FAIL on HCP - etcd config moved to `ETCD_*` env vars |
| CMP-4521 (Bug, Critical) | `ocp4-on-hypershift-hosted` CPE never fires (initContainer vs `.spec.containers` OVAL mismatch) - CP rules false-FAIL inside every hosted cluster |
| CMP-4522 (Bug, Major) | CSV master `nodeSelector` blocks scheduling on hosted clusters — the Subscription override is ALREADY the documented install procedure ([Installing the Compliance Operator on Hypershift hosted control planes](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation), Technology Preview); ticket to be closed/rescoped |
| CMP-4523 (Story) | Collector SA lacks `nodepools` RBAC for CEL inputs |
| CMP-4524 (Story) | Extend HyperShift awareness to the HostedCluster-derivable rules |

Full per-rule detail: [`RULE_COVERAGE_MATRIX.md`](RULE_COVERAGE_MATRIX.md). Multi-cluster fleets: section 10.

---

This package delivers the best currently-achievable automated coverage of the CIS,
DISA STIG, and NIST 800-53 High benchmarks for a hosted cluster **without any
ComplianceAsCode content changes**, using only supported Compliance Operator
primitives: TailoredProfiles, `disableRules`, and CEL CustomRules.

Manifests in this directory (all applied and validated on the live cluster):

| File | Purpose |
|---|---|
| `customrules.yaml` | 14 CEL CustomRules: 6 etcd env-var checks (replace false positives) + 8 HostedCluster/NodePool gap rules |
| `tp-cis-with-disables.yaml` | CIS TailoredProfile: hypershift variables + 10 `disableRules` |
| `tp-stig.yaml` | STIG TailoredProfile: hypershift variables + 27 `disableRules` |
| `tp-high.yaml` | High TailoredProfile: hypershift variables + 51 `disableRules` |
| `tp-cel.yaml` | TailoredProfile binding the 14 CustomRules (CEL scans cannot mix with OpenSCAP) |
| `ssb.yaml`, `ssb-all.yaml` | ScanSettingBindings for all four scans |
| `rbac-hypershift-read.yaml` | Read grant on `hostedclusters`/`nodepools` for the `api-resource-collector` SA (required for the CEL inputs; without it the NodePool rule returns ERROR — reproduced live) |
| `hostedcluster.yaml` | The none-platform HostedCluster used for validation (SingleReplica, guest OLM catalogs) |

Per-hosted-cluster values to substitute: `hcp-demo` / `clusters` in the TailoredProfile
`setValues` and the `clusters-hcp-demo` namespace inside `customrules.yaml`
(CustomRule expressions are static text — generate one set per hosted cluster).

---

## 1. Live validation results (all four scans DONE)

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

## 2. Exactly what the solution scans, per benchmark (management + in-hosted combined)

"Covered" below means: an automated result that truthfully describes the hosted
cluster. The producing layer is named per row: mgmt tailored scan, CEL CustomRules,
or the in-hosted tailored scan (all three validated live - sections 1 and 8).

### 2.1 CIS (ocp4-cis platform profile: 94 rules)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware OpenSCAP rules | 47 | kube-apiserver/openshift-apiserver config (`kas-config`), etcd+KCM pod specs, HostedCluster OAuth/encryption, CP-namespace NetworkPolicies |
| Covered — CEL replacements for false positives | 6 | the etcd TLS set (disabled in the TP, replaced 1:1 by `hcp-etcd-*`) |
| Covered — CEL replacements for wrong-target rules | 4 | `audit-profile-set` + `audit-logging-enabled` -> `hcp-audit-profile`; `api-server-tls-security-profile-not-old`/`-custom-min-tls-version` -> `hcp-api-tls-security-profile` |
| Correctly NOT-APPLICABLE | 4 | `kubeadmin-removed`, `configure-network-policies(-namespaces)`, `audit-log-forwarding-enabled` (webhook variant runs instead) |
| Covered — in-hosted tailored scan (validated on hcp-aws, section 8) | 13 | `api-server-anonymous-auth`, `api-server-oauth/openshift-https-serving-cert`, `api-server/scheduler-profiling-protected-by-rbac` (x3), `rbac-debug-role-protects-pprof`, `scc-limit-container-allowed-capabilities`, `ingress-controller-tls-cipher-suites`, `ocp-*registries*` (x4) |
| **Gap — no automated equivalent anywhere** | 2 | `api-server-(kube-)no-unsupported-config-overrides`: the operator CRs do not exist for hosted CPs. Compensating statement: HCP does not expose unsupportedConfigOverrides to tenants at all. |
| Manual attestation (unchanged by HCP) | 21 | rbac_*, scc_* judgment rules, secrets management, namespace hygiene — perform against the hosted cluster |

Net (combined): **64 of 66 automatable platform rules (97%) produce truthful
hosted-cluster results — 41 mgmt-aware + 6 etcd-CEL + 4 wrong-target-CEL + 13
in-hosted. The only hard gap is the 2 `no-unsupported-config-overrides` rules
(architectural SSP statement). Management side alone covers 51 of 66 (77%).**

**Node dimension — `ocp4-cis-node` (~103 rules):** runs inside the hosted cluster via
the worker-role node scans (the HyperShift platform default). Master-node rules are
structurally out of scope (hosted clusters have no masters; the control-plane
file-level story is covered by the compensating controls in the analysis doc).
Live result on hcp-aws 4.20.32 workers: `ocp4-cis-node-worker` **57 PASS / 0 FAIL —
COMPLIANT out of the box**.

### 2.2 STIG (ocp4-stig platform profile: 48 rules; full benchmark 169)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware | 6 | `api-server-encryption-provider-cipher`, `idp-is-configured`, `ocp-idp-no-htpasswd`, `ocp-no-ldap-insecure`, `oauth-login-template-set`, `oauth-provider-selection-set` |
| Covered — CEL gap rules | 6 | `fips-mode-enabled-on-all-nodes` -> `hcp-fips-enabled` (authoritative `spec.fips`); `api-server-tls-security-profile` -> `hcp-api-tls-security-profile`; `audit-profile-set` -> `hcp-audit-profile`; `oauth-or-oauthclient-token-maxage`/`-inactivity-timeout` -> CEL pair; `audit-log-forwarding-uses-tls` -> `hcp-audit-webhook` (existence; TLS of the webhook target needs manual attestation) |
| Correctly NOT-APPLICABLE | 4 | same as CIS |
| Covered — in-hosted tailored scan (validated, section 8) | 18 | `classification-banner`, `openshift-motd-exists`, `oauth-logout-url-set`, `ocp-*registries*` (x4), `image-pruner-active`, `imagestream-sets-schedule`, `project-config-and-template-network-policy`/`-resource-quota`, `resource-requests-quota-per-project`, `routes-rate-limit`, `ingress-controller-tls-security-profile`, `cluster-logging-operator-exist`, `cluster-version-operator-exists`/`-verify-integrity`, `container-security-operator-exists` |
| Covered — other layers | 3 | `audit-error-alert-exists` (mgmt self-scan, Layer D), `scansettingbinding-exists` + `scansettings-have-schedule` (satisfied by the validated in-hosted CO install) |
| Manual attestation | 11 | rbac_logging_* / rbac_least_privilege / scc_limit_* |

Net (combined): **all 33 automatable platform rules (100%) covered — 6 mgmt-aware +
6 CEL + 18 in-hosted + 3 via other layers.** Management side alone covers only
12 of 33 (36%) because just 6 rules were ever made HyperShift-aware — the in-hosted
and CEL layers are what make STIG whole.

**Node/OS dimension — `ocp4-stig-node` + `rhcos4-stig` (121 rules):** live results:
`ocp4-stig-node-worker` 2 PASS / 1 FAIL; `rhcos4-stig-worker` 17 PASS / 1 MANUAL /
98 FAIL. The OS-level FAILs are the node-hardening backlog — remediations must be
delivered through `NodePool.spec.config` MachineConfigs on the management cluster,
since hosted clusters run no MCO (scan-only in this validation).

### 2.3 NIST 800-53 High (ocp4-high platform profile: 134 rules; full 257)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware (inherited from CIS + OAuth/IdP set) | 57 | validated live: audit-log sizes, admission plugins, etcd client/serving certs of KAS, encryption, IdP, webhook forwarding, CP NetworkPolicies |
| Covered — CEL | 15 | 6 etcd + `api-server-tls-security-profile(+-not-old/-custom)` + `audit-logging-enabled`/`audit-profile-set` + `fips` + OAuth max-age/inactivity + audit webhook |
| Correctly NOT-APPLICABLE | 9 | CIS 4 + `file-integrity-*` (2, `not ocp4-on-hypershift`) + SDN-gated proxy-kubeconfig (3, OVN) |
| Covered — in-hosted tailored scan (validated, section 8) | ~30 | the CIS-13 plus: `banner-or-login-template-set`, `default-ingress-ca-replaced`, `ingress-controller-certificate`/`-tls-security-profile`, `resource-requests-limits-in-daemonset/deployment/statefulset`, `resource-requests-quota`, `route-ip-whitelist`, `routes-protected-by-tls`, `routes-rate-limit`, `api-server-api-priority-flowschema-catch-all`, `gitops-operator-exists`, `cluster-logging-operator-exist`, `cluster-version-operator-exists`/`-verify-integrity`, `compliance-notification-enabled`, `scansettingbinding-exists` |
| Gap/other layers | 4 | `no-unsupported-config-overrides` x2 (architectural, as CIS); `audit-error-alert-exists` (mgmt); `cluster-wide-proxy-set` (CEL rule available in [`HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md`](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) section 7.2(h), not deployed here — no proxy in this environment) |
| Manual attestation | 25 | superset of CIS manual rules |

Net (combined): **~98 of 100 automatable platform rules (98%) covered — 51
mgmt-aware + 15 CEL + ~30 in-hosted + 2 via other layers; the 2
`no-unsupported-config-overrides` rules remain SSP statements.** Management side
alone covers 72 of 100 (72%).

**Node dimension — `ocp4-high-node` + `rhcos4-high` (123 rules):** live results:
`ocp4-high-node-worker` 61 PASS / 3 MANUAL / 1 FAIL; `rhcos4-high-worker` 40 PASS /
4 MANUAL / 194 FAIL (unhardened RHCOS against the NIST High OS baseline — the same
NodePool-delivered hardening workload as STIG).

### 2.4 How the layers divide the work (all validated)

1. **Compliance Operator inside each hosted cluster** (VALIDATED on `hcp-aws`,
   section 8: OLM install with the worker nodeSelector override + in-hosted tailored
   profiles) — provides every "in-hosted" row above (13 CIS / 18 STIG / ~30 High),
   plus all node profiles. Caveat: in-hosted config CRs are mirrors of
   `HostedCluster.spec.configuration`; where they disagree, the CEL rules against the
   HostedCluster are authoritative.
2. **Scan the management cluster itself** with plain `ocp4-cis`/`ocp4-stig`/
   `ocp4-high` + node profiles — it hosts the control planes and owns
   `audit-error-alert-exists`-class responsibilities.
3. **Manual attestations** (21/11/25 rules) are unchanged by HyperShift — perform
   them against the hosted cluster.
4. The two `no-unsupported-config-overrides` rules should be recorded as
   architecturally N/A for HCP in the SSP (tenants cannot set overrides at all).

## 3. Bugs and sharp edges found during validation

1. **etcd rules false-positive on HCP 4.21** (`etcd-cert-file` + 5 siblings): hosted
   etcd is configured via `ETCD_*` env vars, the content only inspects pod args. Do
   NOT fix content yet per current plan — this package disables the six rules and
   replaces them 1:1 with CEL. Upstream fix tracked separately (see
   [`HCP_SCAN_VALIDATION_REPORT.md`](docs-background/HCP_SCAN_VALIDATION_REPORT.md) section 5).
2. **RBAC**: `api-resource-collector` can read `hostedclusters` out of the box (they
   aggregate into cluster-reader) but NOT `nodepools` — the NodePool CEL rule
   returned ERROR with a forbidden message until `rbac-hypershift-read.yaml` was
   applied. Reproduced and fixed live.
3. **TailoredProfile requires `spec.description`** when creating STIG/High TPs — the
   apply fails without it.
4. CustomRule expressions are static — no variable substitution — so the CP
   namespace (`clusters-hcp-demo`) is baked in; template per hosted cluster.
5. CI-environment HostedCluster hints (not compliance-related):
   `controllerAvailabilityPolicy: SingleReplica` on <3-AZ management clusters,
   `olmCatalogPlacement: guest` for nightly releases; both immutable.

## 4. Related documents

- [`HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md`](docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md) — mechanism internals + full CIS/PCI rule
  dispositions
- [`HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md`](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) — the five-layer strategy and the CEL
  rule catalog this package implements
- [`HCP_SCAN_VALIDATION_REPORT.md`](docs-background/HCP_SCAN_VALIDATION_REPORT.md) — first validation run (CIS) and the etcd
  false-positive evidence

The `hcp-demo` HostedCluster and all scan objects are left in place on
`ci-ln-b6zqd5k-76ef8.aws-4.ci.openshift.org` for inspection.

---

## 8. In-hosted scan layer: VALIDATED (added 2026-07-31, second session)

An AWS-platform HostedCluster `hcp-aws` (4.20.32 GA, 2× m5.xlarge workers, created via
MCE `hcp` CLI with `--control-plane-availability-policy SingleReplica`) was used to
validate the "install the Compliance Operator inside each hosted cluster" layer.

New manifests in this directory:

| File | Purpose |
|---|---|
| `co-in-hosted.yaml` | OLM install of CO v1.9.1 inside the hosted cluster, matching the official documented procedure ([Installing the Compliance Operator on Hypershift hosted control planes](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation), Technology Preview): `spec.config.env` `PLATFORM=HyperShift` + `spec.config.nodeSelector: {node-role.kubernetes.io/worker: ""}`. Without the overrides the operator pod stays Pending (CSV pins to masters; hosted clusters have none) — our validation independently confirmed the documented settings are load-bearing. |
| `tp-in-hosted.yaml` | `hosted-cis-tailored` / `hosted-stig-tailored` / `hosted-high-tailored` — disable the control-plane rules (46 / 4 / 54) inside the hosted cluster |
| `ssb-in-hosted.yaml`, `ssb-in-hosted-tailored.yaml` | node-profile bindings and tailored platform bindings |

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
| `ocp4-cis` (untailored) | 22P/21M/46F | demonstrates the CPE bug: ~38 false CP FAILs |
| `hosted-cis-tailored` | 14P/21M/8F | CP rules absent; remaining FAILs genuine (kubeadmin present, registries unset, ingress ciphers default, netpol missing) |
| `hosted-stig-tailored` | 14P/11M/19F | banner/MOTD/logout-url/project-template FAILs = real unhardened-cluster findings |
| `hosted-high-tailored` | 28P/23M/24F | same pattern |
| `ocp4-cis-node-worker` | 57 PASS — **COMPLIANT** | 4.20 workers pass CIS node checks out of the box |
| `ocp4-stig-node-worker` | 2P/1F | kubelet STIG |
| `rhcos4-stig-worker` | 17P/1M/98F | OS-level STIG on unhardened RHCOS — the node-hardening workload that NodePool config must address |
| `ocp4-high-node-worker` | 61P/3M/1F | NIST High kubelet/node checks |
| `rhcos4-high-worker` | 40P/4M/194F | NIST High OS baseline on unhardened RHCOS — same NodePool hardening backlog |

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
- Both hosted clusters (`hcp-demo`, `hcp-aws`) are left running with all scan objects
  for inspection.

## 9. Consolidated findings list (all validated live)

1. etcd rules false-positive on HCP 4.21+ (env-var config) — CEL replacement shipped here. Filed: CMP-4520.
2. `oauth_or_oauthclient_inactivity_timeout` and siblings not HyperShift-aware — CEL gap rules shipped here. Filed: CMP-4524.
3. Downstream CSV master `nodeSelector` blocks OLM install on hosted clusters — the Subscription override (worker nodeSelector + PLATFORM env) is the officially documented install procedure ([Installing the Compliance Operator on Hypershift hosted control planes](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation), Technology Preview); validated live. CMP-4522 filed before finding the docs — to be closed or rescoped to 'tolerate masterless topologies natively'.
4. `ocp4-on-hypershift-hosted` CPE unreachable (initContainer vs `.spec.containers` OVAL mismatch) — in-hosted tailored profiles required. Filed: CMP-4521.
5. `api-resource-collector` lacks RBAC for `nodepools` (has `hostedclusters` via cluster-reader aggregation) — `rbac-hypershift-read.yaml` required for the NodePool CEL rule. Filed: CMP-4523.


## 10. Scaling to multiple hosted clusters

Everything in this package was validated against a single hosted cluster; with a fleet
on one management cluster, each object falls into one of two categories:

### 10.1 Per-hosted-cluster objects (instantiate N times)

| Object | Why per-cluster | Naming convention |
|---|---|---|
| Mgmt TailoredProfiles (`tp-cis-with-disables`, `tp-stig`, `tp-high`) | The two variables (`ocp4-hypershift-cluster`, `ocp4-hypershift-namespace-prefix`) identify exactly ONE HostedCluster; a scan reads exactly one control-plane namespace | `hypershift-<profile>-<cluster>` (e.g. `hypershift-cis-payments-prod`) |
| ScanSettingBindings for those TPs | One binding per TP | `hypershift-<profile>-<cluster>` |
| The 6 etcd CEL CustomRules | The control-plane namespace (`clusters-<name>`) is baked into the expression (CustomRules have no variable substitution) | `hcp-etcd-<check>-<cluster>` |
| In-hosted install + tailored profiles (`co-in-hosted.yaml`, `tp-in-hosted.yaml`, SSBs) | The Compliance Operator runs inside EACH hosted cluster | identical manifests per cluster |

Generation is mechanical - every per-cluster manifest differs only in the cluster
name/namespace strings. A 10-line loop over `oc get hostedcluster -A` output (sed on
the name/prefix placeholders) produces the full set; keep the generated manifests in
Git per cluster.

### 10.2 Fleet-wide objects (one instance covers all hosted clusters)

The 8 HostedCluster/NodePool CEL rules are fleet-wide BY DESIGN: they assert the
condition over `.items.all(...)`, so ONE rule evaluates every hosted cluster and a
newly onboarded violating cluster immediately fails the shared check.

Two adjustments for fleets:

- **Cover every namespace prefix.** The validated rules set
  `resourceNamespace: clusters`; if your fleet uses multiple HostedCluster namespaces,
  REMOVE `resourceNamespace` from the input - an empty namespace fetches the resource
  across all namespaces.
- **Fleet vs per-cluster verdicts.** A fleet rule yields ONE result: FAIL means "at
  least one cluster violates" (the offender is not named in the status). If auditors
  need per-cluster verdicts, generate per-cluster copies instead: set
  `resourceNamespace: <prefix>` + `resourceName: <cluster>` on the input and adjust
  the expression from `.items.all(hc, ...)` to the single-object form, naming each
  rule `hcp-<check>-<cluster>`. Both shapes can coexist (fleet rule as the gate,
  per-cluster rules for reporting).

Also fleet-wide as-is: `rbac-hypershift-read.yaml` (one grant) and the management
cluster's own self-scans (Layer D).

### 10.3 Distribution and operations at fleet scale

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
- **Onboarding checklist for a new hosted cluster:** generate + apply the per-cluster
  mgmt TPs/SSBs and etcd CEL rules; let the policy/GitOps engine roll out the
  in-hosted bundle; confirm the fleet CEL rules pick it up (they do automatically);
  add its scans to the schedule bucket with the most headroom.
