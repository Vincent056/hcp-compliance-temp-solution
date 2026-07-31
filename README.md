# Temporary Compliance Solution for Hosted Control Planes: CIS + STIG + NIST 800-53 High

**Status: VALIDATED end-to-end on a live cluster, 2026-07-31.**
Environment: OCP 4.21.0 nightly management cluster (AWS), Compliance Operator **v1.9.1**
(downstream), MCE **v2.17.1**, HostedCluster `hcp-demo` (none-platform, CP-only,
left running for further testing). Scan-only: no remediations were applied
(`default` ScanSetting, auto-apply off).

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

## 2. Exactly what the management-side temp solution scans, per benchmark

"Covered" below means: an automated result that truthfully describes the hosted
cluster, produced from the management cluster by this package.

### 2.1 CIS (ocp4-cis platform profile: 94 rules)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware OpenSCAP rules | 47 | kube-apiserver/openshift-apiserver config (`kas-config`), etcd+KCM pod specs, HostedCluster OAuth/encryption, CP-namespace NetworkPolicies |
| Covered — CEL replacements for false positives | 6 | the etcd TLS set (disabled in the TP, replaced 1:1 by `hcp-etcd-*`) |
| Covered — CEL replacements for wrong-target rules | 4 | `audit-profile-set` + `audit-logging-enabled` -> `hcp-audit-profile`; `api-server-tls-security-profile-not-old`/`-custom-min-tls-version` -> `hcp-api-tls-security-profile` |
| Correctly NOT-APPLICABLE | 4 | `kubeadmin-removed`, `configure-network-policies(-namespaces)`, `audit-log-forwarding-enabled` (webhook variant runs instead) |
| **Gap — needs a scan inside the hosted cluster** | 13 | `api-server-anonymous-auth`, `api-server-oauth/openshift-https-serving-cert`, `api-server/scheduler-profiling-protected-by-rbac` (x3), `rbac-debug-role-protects-pprof`, `scc-limit-container-allowed-capabilities`, `ingress-controller-tls-cipher-suites`, `ocp-*registries*` (x4) |
| **Gap — no automated equivalent anywhere** | 2 | `api-server-(kube-)no-unsupported-config-overrides`: the operator CRs do not exist for hosted CPs. Compensating statement: HCP does not expose unsupportedConfigOverrides to tenants at all. |
| Manual attestation (unchanged by HCP) | 21 | rbac_*, scc_* judgment rules, secrets management, namespace hygiene — perform against the hosted cluster |
| Out of scope of the platform profile | ~103 node rules | `ocp4-cis-node` + `rhcos4-*` inside the hosted cluster (needs workers; this demo cluster has none) |

Net: **57 of 73 automatable platform rules (78%) produce truthful hosted-cluster
results from the management side; 13 need an in-hosted scan; 2 are architectural
N/A; 1 wrong-target pair is CEL-covered.**

### 2.2 STIG (ocp4-stig platform profile: 48 rules; full benchmark 169)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware | 6 | `api-server-encryption-provider-cipher`, `idp-is-configured`, `ocp-idp-no-htpasswd`, `ocp-no-ldap-insecure`, `oauth-login-template-set`, `oauth-provider-selection-set` |
| Covered — CEL gap rules | 6 | `fips-mode-enabled-on-all-nodes` -> `hcp-fips-enabled` (authoritative `spec.fips`); `api-server-tls-security-profile` -> `hcp-api-tls-security-profile`; `audit-profile-set` -> `hcp-audit-profile`; `oauth-or-oauthclient-token-maxage`/`-inactivity-timeout` -> CEL pair; `audit-log-forwarding-uses-tls` -> `hcp-audit-webhook` (existence; TLS of the webhook target needs manual attestation) |
| Correctly NOT-APPLICABLE | 4 | same as CIS |
| **Gap — needs in-hosted scan** | 18 | `classification-banner`, `openshift-motd-exists`, `oauth-logout-url-set`, `ocp-*registries*` (x4), `image-pruner-active`, `imagestream-sets-schedule`, `project-config-and-template-network-policy`/`-resource-quota`, `resource-requests-quota-per-project`, `routes-rate-limit`, `ingress-controller-tls-security-profile`, `cluster-logging-operator-exist`, `cluster-version-operator-exists`/`-verify-integrity`, `container-security-operator-exists` |
| **Gap — management-side responsibility** | 3 | `audit-error-alert-exists` (alerting where the hosted KAS actually runs), `scansettingbinding-exists` + `scansettings-have-schedule` (satisfied by installing CO in the hosted cluster) |
| Manual attestation | 11 | rbac_logging_* / rbac_least_privilege / scc_limit_* |
| Node/OS dimension | 121 | `ocp4-stig-node` + `rhcos4-stig` inside the hosted cluster |

Net: **12 of 37 automatable platform rules (32%) truthfully covered from the
management side; 18 recoverable by an in-hosted platform scan; 3 belong to the
management cluster's own posture.** STIG remains the weakest profile for
management-side scanning because only 6 rules were ever made HyperShift-aware.

### 2.3 NIST 800-53 High (ocp4-high platform profile: 134 rules; full 257)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware (inherited from CIS + OAuth/IdP set) | 57 | validated live: audit-log sizes, admission plugins, etcd client/serving certs of KAS, encryption, IdP, webhook forwarding, CP NetworkPolicies |
| Covered — CEL | 15 | 6 etcd + `api-server-tls-security-profile(+-not-old/-custom)` + `audit-logging-enabled`/`audit-profile-set` + `fips` + OAuth max-age/inactivity + audit webhook |
| Correctly NOT-APPLICABLE | 9 | CIS 4 + `file-integrity-*` (2, `not ocp4-on-hypershift`) + SDN-gated proxy-kubeconfig (3, OVN) |
| **Gap — needs in-hosted scan** | ~30 | the CIS-13 plus: `banner-or-login-template-set`, `default-ingress-ca-replaced`, `ingress-controller-certificate`/`-tls-security-profile`, `resource-requests-limits-in-daemonset/deployment/statefulset`, `resource-requests-quota`, `route-ip-whitelist`, `routes-protected-by-tls`, `routes-rate-limit`, `api-server-api-priority-flowschema-catch-all`, `gitops-operator-exists`, `cluster-logging-operator-exist`, `cluster-version-operator-exists`/`-verify-integrity`, `compliance-notification-enabled`, `scansettingbinding-exists` |
| **Gap — other** | 4 | `no-unsupported-config-overrides` x2 (architectural, as CIS); `audit-error-alert-exists` (mgmt); `cluster-wide-proxy-set` (CEL rule available in `docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md` section 7.2(h), not deployed here — no proxy in this environment) |
| Manual attestation | 25 | superset of CIS manual rules |
| Node dimension | 123 | in-hosted node profiles |

Net: **72 of ~100 automatable platform rules (~72%) truthfully covered from the
management side.**

### 2.4 What closes the remaining gaps (production picture)

1. **Install the Compliance Operator inside each hosted cluster** (needs worker
   nodes; not possible on this CP-only demo) and run the platform profiles there —
   that recovers every "needs in-hosted scan" row above (13 CIS / 18 STIG / ~30
   High), plus all node profiles. Caveat: in-hosted config CRs are mirrors of
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
   `docs-background/HCP_SCAN_VALIDATION_REPORT.md` section 5).
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

- `docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md` — mechanism internals + full CIS/PCI rule
  dispositions
- `docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md` — the five-layer strategy and the CEL
  rule catalog this package implements
- `docs-background/HCP_SCAN_VALIDATION_REPORT.md` — first validation run (CIS) and the etcd
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
| `co-in-hosted.yaml` | OLM install of CO v1.9.1 inside the hosted cluster. REQUIRED deviations from a standard install: `spec.config.env` `PLATFORM=HyperShift` AND `spec.config.nodeSelector: {node-role.kubernetes.io/worker: ""}` — the CSV pins the operator to master nodes, which do not exist in hosted clusters (pod stays Pending forever without the override). |
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

Gap-rule recovery verified rule-by-rule: every rule the coverage matrix assigns to
"Hosted scan" produced a genuine in-hosted result — `kubeadmin-removed` FAIL (true:
fresh cluster), `ocp-allowed-registries` FAIL, `ingress-controller-tls-cipher-suites`
FAIL, `api-server-anonymous-auth` PASS, `scc-limit-container-allowed-capabilities`
PASS, `api-server-profiling-protected-by-rbac` PASS,
`configure-network-policies-namespaces` FAIL, STIG `classification-banner` /
`openshift-motd-exists` / `oauth-logout-url-set` FAIL, `image-pruner-active` PASS.

`RULE_COVERAGE_MATRIX.md` now carries live results from BOTH scan locations for every
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

1. etcd rules false-positive on HCP 4.21+ (env-var config) — CEL replacement shipped here.
2. `oauth_or_oauthclient_inactivity_timeout` and siblings not HyperShift-aware — CEL gap rules shipped here.
3. Downstream CSV master `nodeSelector` blocks OLM install on hosted clusters — Subscription override required.
4. `ocp4-on-hypershift-hosted` CPE unreachable (initContainer vs `.spec.containers` OVAL mismatch) — in-hosted tailored profiles required.
5. `api-resource-collector` lacks RBAC for `nodepools` (has `hostedclusters` via cluster-reader aggregation) — `rbac-hypershift-read.yaml` required for the NodePool CEL rule.
