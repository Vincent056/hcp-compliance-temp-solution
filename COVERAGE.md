# Per-benchmark coverage: what covers each rule

**Docs:** [README](README.md) · [Runbook](RUNBOOK.md) · [Coverage](COVERAGE.md) · [Design](DESIGN.md) · [Validation](VALIDATION.md) · [Rule Matrix](RULE_COVERAGE_MATRIX.md) · [Background: Scan Mechanics](docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md) · [Background: Strategy](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) · [Background: First Validation](docs-background/HCP_SCAN_VALIDATION_REPORT.md)

## Scope: what the solution scans, per benchmark (management + in-hosted combined)

"Covered" below means: an automated result that truthfully describes the hosted
cluster - NOT necessarily a vendor-supported one; the support boundary per layer
is in [`README.md`](README.md) ("Official support boundary"). The producing layer is named per row: mgmt tailored scan, CEL CustomRules,
or the in-hosted tailored scan (all three validated live - [`VALIDATION.md`](VALIDATION.md)).

### CIS (ocp4-cis platform profile: 94 rules)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware OpenSCAP rules | 47 | kube-apiserver/openshift-apiserver config (`kas-config`), etcd+KCM pod specs, HostedCluster OAuth/encryption, CP-namespace NetworkPolicies |
| Covered — CEL replacements for false positives | 6 | the etcd TLS set (disabled in the TP, replaced 1:1 by `hcp-etcd-*`) |
| Covered — CEL replacements for wrong-target rules | 4 | `audit-profile-set` + `audit-logging-enabled` -> `hcp-audit-profile`; `api-server-tls-security-profile-not-old`/`-custom-min-tls-version` -> `hcp-api-tls-security-profile` |
| Correctly NOT-APPLICABLE | 4 | `kubeadmin-removed`, `configure-network-policies(-namespaces)`, `audit-log-forwarding-enabled` (webhook variant runs instead) |
| Covered — in-hosted tailored scan (validated on hcp-aws - [`VALIDATION.md`](VALIDATION.md)) | 13 | `api-server-anonymous-auth`, `api-server-oauth/openshift-https-serving-cert`, `api-server/scheduler-profiling-protected-by-rbac` (x3), `rbac-debug-role-protects-pprof`, `scc-limit-container-allowed-capabilities`, `ingress-controller-tls-cipher-suites`, `ocp-*registries*` (x4) |
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

### STIG (ocp4-stig platform profile: 48 rules; full benchmark 169)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware | 6 | `api-server-encryption-provider-cipher`, `idp-is-configured`, `ocp-idp-no-htpasswd`, `ocp-no-ldap-insecure`, `oauth-login-template-set`, `oauth-provider-selection-set` |
| Covered — CEL gap rules | 6 | `fips-mode-enabled-on-all-nodes` -> `hcp-fips-enabled` (authoritative `spec.fips`); `api-server-tls-security-profile` -> `hcp-api-tls-security-profile`; `audit-profile-set` -> `hcp-audit-profile`; `oauth-or-oauthclient-token-maxage`/`-inactivity-timeout` -> CEL pair; `audit-log-forwarding-uses-tls` -> `hcp-audit-webhook` (existence; TLS of the webhook target needs manual attestation) |
| Correctly NOT-APPLICABLE | 4 | same as CIS |
| Covered — in-hosted tailored scan (validated - [`VALIDATION.md`](VALIDATION.md)) | 18 | `classification-banner`, `openshift-motd-exists`, `oauth-logout-url-set`, `ocp-*registries*` (x4), `image-pruner-active`, `imagestream-sets-schedule`, `project-config-and-template-network-policy`/`-resource-quota`, `resource-requests-quota-per-project`, `routes-rate-limit`, `ingress-controller-tls-security-profile`, `cluster-logging-operator-exist`, `cluster-version-operator-exists`/`-verify-integrity`, `container-security-operator-exists` |
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

### NIST 800-53 High (ocp4-high platform profile: 134 rules; full 257)

| Disposition | Count | Rules / notes |
|---|---|---|
| Covered — HyperShift-aware (inherited from CIS + OAuth/IdP set) | 57 | validated live: audit-log sizes, admission plugins, etcd client/serving certs of KAS, encryption, IdP, webhook forwarding, CP NetworkPolicies |
| Covered — CEL | 15 | 6 etcd + `api-server-tls-security-profile(+-not-old/-custom)` + `audit-logging-enabled`/`audit-profile-set` + `fips` + OAuth max-age/inactivity + audit webhook |
| Correctly NOT-APPLICABLE | 9 | CIS 4 + `file-integrity-*` (2, `not ocp4-on-hypershift`) + SDN-gated proxy-kubeconfig (3, OVN) |
| Covered — in-hosted tailored scan (validated - [`VALIDATION.md`](VALIDATION.md)) | ~30 | the CIS-13 plus: `banner-or-login-template-set`, `default-ingress-ca-replaced`, `ingress-controller-certificate`/`-tls-security-profile`, `resource-requests-limits-in-daemonset/deployment/statefulset`, `resource-requests-quota`, `route-ip-whitelist`, `routes-protected-by-tls`, `routes-rate-limit`, `api-server-api-priority-flowschema-catch-all`, `gitops-operator-exists`, `cluster-logging-operator-exist`, `cluster-version-operator-exists`/`-verify-integrity`, `compliance-notification-enabled`, `scansettingbinding-exists` |
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

### How the layers divide the work (all validated)

1. **Compliance Operator inside each hosted cluster** (VALIDATED on `hcp-aws` -
   [`VALIDATION.md`](VALIDATION.md): OLM install with the worker nodeSelector override + in-hosted tailored
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

