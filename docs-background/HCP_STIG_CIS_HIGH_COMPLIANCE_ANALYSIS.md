# Reaching STIG, CIS, and NIST 800-53 High Compliance for Self-Managed Hosted Control Planes

**Docs:** [Solution README](../README.md) · [Rule Coverage Matrix](../RULE_COVERAGE_MATRIX.md) · [Scan Mechanics Guide](HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md) · [Strategy & Gap Analysis](HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) · [Validation Report](HCP_SCAN_VALIDATION_REPORT.md)

## TL;DR

The strategy document: how to reach CIS, STIG, and NIST High for hosted clusters
using five layers (in-hosted platform scans, in-hosted node scans, management
tailored scans, management self-scans, CEL CustomRules on HostedCluster/NodePool
spec). Contains the per-profile gap classification that sized the problem
(STIG has only 6 HyperShift-aware rules; High inherits all 57 from CIS), the CEL
rule catalog (since implemented as `customrules.yaml` and validated 14/14), the
NodePool MachineConfig remediation transport, and the upstream fixes (since filed —
see errata). For current live numbers use the Solution README and the matrix.

> **Post-validation errata (2026-07-31).** All five layers proposed here were
> subsequently validated live (see the repo README and RULE_COVERAGE_MATRIX.md).
> Corrections against reality:
>
> 1. Layer A's premise that control-plane rules go NOT-APPLICABLE in-hosted via the
>    `ocp4-on-hypershift-hosted` CPE does not hold today - the CPE is unreachable
>    (CMP-4521); use in-hosted TailoredProfiles that disable the CP rules instead.
> 2. The RBAC prediction in section 7.1 was confirmed exactly: `hostedclusters`
>    readable via cluster-reader aggregation, `nodepools` forbidden (CMP-4523).
> 3. The downstream CSV pins the operator to master nodes; the required Subscription
>    override (worker nodeSelector + PLATFORM env) turned out to be the officially
>    [documented HyperShift install procedure](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#installing-compliance-operator-hcp_compliance-operator-installation) (Technology Preview) - CMP-4522 filed
>    before finding the docs, to be closed or rescoped.
> 4. The section 7.2 CEL catalog was implemented and validated 14/14
>    (`customrules.yaml`); the upstream work in section 9 is filed as CMP-4520 and
>    CMP-4524.

**Audience:** customers and support engineers who manage their own Hosted Control Planes
(HyperShift) environment and need to satisfy DISA STIG, CIS OpenShift Benchmark, and
NIST 800-53 High-impact baselines for their hosted clusters.

**Assumption:** the customer already runs the node profiles (`ocp4-*-node`, `rhcos4-*`)
inside the hosted clusters. This document covers everything *beyond* that: what to run
where, exactly which rules cannot produce meaningful results, and how to close the gaps
with CEL CustomRules, NodePool configuration, and management-cluster scans.

**Companion document:** `HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md` — mechanics of the
management-cluster tailored scan (variables, CPE detection, dual-path rules) and the
full CIS/PCI-DSS rule dispositions. This document builds on it and does not repeat the
mechanism details.

Analysis is based on ComplianceAsCode/content (CIS v1.9.0, STIG v2r3, NIST 800-53 rev-4
controls for OCP4) and the current Compliance Operator source, July 2026.

---

## 1. Executive summary

| Profile | Official HCP mgmt-scan support | Hosted-CP config coverage today | Main gap-closing tools |
|---|---|---|---|
| `ocp4-cis` | Yes (TailoredProfile with HyperShift variables) | 47 of 94 platform rules are HyperShift-aware | Mgmt tailored scan + in-hosted platform scan + `disableRules` |
| `ocp4-high` | No (not in the supported list) | Inherits all CIS awareness (57 aware of 134 platform rules) because `ocp4-high` extends `cis` | Same recipe as CIS (technically works, unsupported) + CEL CustomRules |
| `ocp4-stig` | No | Only 6 of 48 platform rules are HyperShift-aware | In-hosted platform scan covers most; CEL CustomRules for control-plane config; upstream RFE |

Five coverage layers, all of which should be deployed together:

- **Layer A — in-hosted platform scans**: install the Compliance Operator *inside* each
  hosted cluster (`PLATFORM=HyperShift` build/deployment) and run `ocp4-cis`,
  `ocp4-stig`, `ocp4-high` there, not just the node profiles. This is the single
  biggest win: the majority of "wrong-target" rules from the management scan are
  in-cluster checks (SCC, RBAC, registries, routes, MOTD, banners, quotas, operators)
  that evaluate correctly inside the hosted cluster.
- **Layer B — in-hosted node scans**: what the customer already runs. One caveat
  (section 6): scanning works, but MachineConfig remediations cannot be applied inside
  a hosted cluster — they must be transported to `NodePool` configuration on the
  management cluster.
- **Layer C — management-cluster tailored scans**: the HyperShift-variable
  TailoredProfile per hosted cluster. Supported for CIS (and PCI-DSS); technically
  functional for STIG and High because both ship the `version_detect_in_hypershift`
  helper (STIG directly, High by extending CIS) — but outside the official support
  statement, so results need validation and Red Hat support may decline issues.
- **Layer D — management-cluster self scans**: plain `ocp4-stig` / `ocp4-cis` /
  `ocp4-high` plus node profiles on the management cluster itself. The management
  cluster hosts the control planes; its own hardening is part of the hosted clusters'
  security boundary (SCCs, RBAC and NetworkPolicies there protect the CP pods).
- **Layer E — CEL CustomRules on the management cluster**: for settings whose source of
  truth is the `HostedCluster`/`NodePool` spec (FIPS, etcd secret encryption, audit
  profile, TLS security profile, OAuth token policy, audit webhook, proxy). Section 7
  provides ready-to-use rules.

What remains genuinely open after all five layers is listed in section 8.

## 2. Why the gaps exist (short version)

A scan can only query the API server of the cluster it runs in. Hosted control planes
live as pods in `<prefix>-<name>` namespaces on the management cluster; the hosted
cluster itself contains only workers and workloads. Content rules become
HyperShift-aware by templating their fetch path with
`{{.hypershift_namespace_prefix}}-{{.hypershift_cluster}}` (dual-path mechanism, see
companion doc). Rules without that templating read whatever cluster the operator is
installed in — on the management scan they silently assess the *management* cluster.

Additional HCP-specific facts that shape the analysis:

- With `PLATFORM=HyperShift`, the operator defaults to the `worker` role only
  (`cmd/manager/operator.go:139-141`) — hosted clusters expose no master nodes, so all
  `ocp4-master-node`-gated rules are out of scope in-hosted (etcd/apiserver file
  checks, etc.).
- Hosted clusters do not run the Machine Config Operator; worker node configuration
  flows from `NodePool.spec.config` ConfigMaps on the management cluster. This breaks
  the remediation half of node profiles (section 6), not the scanning half.
- The authoritative configuration for a hosted cluster's control plane is
  `HostedCluster.spec` (e.g. `.spec.fips`, `.spec.secretEncryption`,
  `.spec.configuration.apiServer/oauth/image/proxy`), which only exists on the
  management cluster — the natural target for CEL CustomRules.

## 3. Profile-by-profile analysis

### 3.1 ocp4-cis (baseline, fully covered in the companion doc)

Platform profile: 94 rules after node filtering. 47 HyperShift-aware, 4 auto-N/A on the
management scan, 43 wrong-target (19 automated + 21 manual + 3 SDN-gated). Recipe:
mgmt tailored scan with the 19 automated wrong-target rules disabled, in-hosted
`ocp4-cis` scan for the in-cluster half, manual rules attested against the hosted
cluster. Full lists and a ready TailoredProfile are in
`HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md`.

### 3.2 ocp4-stig (v2r3)

The STIG control file selects 169 rules; after node/OS filtering the *platform* profile
carries 48. Classification for a management-cluster tailored scan:

**HyperShift-aware (6):**
`api_server_encryption_provider_cipher` (reads `HostedCluster.spec.secretEncryption.type`),
`idp_is_configured`, `ocp_idp_no_htpasswd`, `ocp_no_ldap_insecure`,
`oauth_login_template_set`, `oauth_provider_selection_set`
(all read `HostedCluster.spec.configuration.oauth`).

**Auto-N/A on the management scan (4):** `audit_log_forwarding_enabled`,
`configure_network_policies`, `configure_network_policies_namespaces`,
`kubeadmin_removed`.

**Wrong-target on a management scan (38: 27 automated, 11 manual):**

| Disposition | Rules |
|---|---|
| Layer A (in-hosted scan gives the correct answer) | `classification_banner`, `cluster_logging_operator_exist`, `cluster_version_operator_exists`, `cluster_version_operator_verify_integrity`, `container_security_operator_exists`, `image_pruner_active`, `imagestream_sets_schedule`, `ingress_controller_tls_security_profile`, `oauth_logout_url_set`, `ocp_allowed_registries`, `ocp_allowed_registries_for_import`, `ocp_insecure_allowed_registries_for_import`, `ocp_insecure_registries`, `openshift_motd_exists`, `project_config_and_template_network_policy`, `project_config_and_template_resource_quota`, `resource_requests_quota_per_project`, `routes_rate_limit`, `scansettingbinding_exists`, `scansettings_have_schedule` |
| Layer E (CEL CustomRule against HostedCluster, section 7) | `api_server_tls_security_profile`, `audit_profile_set`, `oauth_or_oauthclient_inactivity_timeout`, `oauth_or_oauthclient_token_maxage`, `fips_mode_enabled_on_all_nodes`, `audit_log_forwarding_uses_tls` (webhook variant) |
| Layer A or D + manual judgment | `audit_error_alert_exists` (the alert matters on the mgmt cluster, where the hosted KAS runs) |
| Manual (attest against the hosted cluster) | `rbac_least_privilege`, `rbac_logging_del`, `rbac_logging_mod`, `rbac_logging_view`, `scc_limit_host_dir_volume_plugin`, `scc_limit_host_ports`, `scc_limit_ipc_namespace`, `scc_limit_network_namespace`, `scc_limit_privileged_containers`, `scc_limit_process_id_namespace`, `scc_limit_root_containers` |

Notes:

- A management tailored scan extending `ocp4-stig` *does* function mechanically:
  `stig-v2r3.profile` includes `version_detect_in_hypershift`, so setting the two
  variables flips the `ocp4-on-hypershift` CPE, the 4 auto-N/A rules suppress
  correctly, and the 6 aware rules read the HostedCluster. It is simply not in the
  supported-profiles list (see [Configuring the hosted control planes management cluster](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#co-hcp-mgmt-config_compliance-operator-scans)).
  Decision for the customer: run it with the wrong-target
  rules disabled and document the support caveat, or skip Layer C for STIG and rely on
  Layers A + E entirely.
- STIG's node/OS dimension (121 of 169 rules) is the bulk of the benchmark and is
  covered by `ocp4-stig-node` + `rhcos4-stig` in the hosted cluster (Layer B) and on
  the management cluster (Layer D).

### 3.3 ocp4-high (NIST 800-53 High, rev-4)

`ocp4-high` **extends the CIS profile** and adds `nist_ocp4:all:high`. The union is 257
rules; the platform half classifies as: **57 HyperShift-aware, 6 auto-N/A, 71
wrong-target (46 automated, 25 manual), 123 node-scoped.**

Because it inherits CIS, all 47 CIS-aware rules carry over (plus
`oauth_login_template_set`-class rules), and the CIS wrong-target dispositions apply
unchanged. The High-specific additions beyond CIS are 28 wrong-target rules:

| Disposition | Rules |
|---|---|
| Layer A (in-hosted) | `api_server_api_priority_flowschema_catch_all`, `banner_or_login_template_set`*, `cluster_logging_operator_exist`, `cluster_version_operator_exists`, `cluster_version_operator_verify_integrity`, `compliance_notification_enabled`, `default_ingress_ca_replaced`, `gitops_operator_exists`, `ingress_controller_certificate`, `ingress_controller_tls_security_profile`, `openshift_motd_exists`, `resource_requests_limits_in_daemonset`, `resource_requests_limits_in_deployment`, `resource_requests_limits_in_statefulset`, `resource_requests_quota`, `route_ip_whitelist`, `routes_protected_by_tls`, `routes_rate_limit`, `scansettingbinding_exists` |
| Layer E (CEL against HostedCluster) | `api_server_tls_security_profile`, `cluster_wide_proxy_set`, `fips_mode_enabled_on_all_nodes`, `oauth_or_oauthclient_inactivity_timeout`, `oauth_or_oauthclient_token_maxage` |
| Layer D (management-cluster concern for the hosted CP) | `audit_error_alert_exists`, `audit_log_forwarding_uses_tls` |
| Manual | `alert_receiver_configured`, `general_configure_imagepolicywebhook` |

*`banner_or_login_template_set` is a near-miss: its STIG siblings
(`oauth_login_template_set`, `oauth_provider_selection_set`) are already
HyperShift-aware via `HostedCluster.spec.configuration.oauth.templates` — making this
rule aware upstream is trivial (see section 9).

A management tailored scan extending `ocp4-high` inherits the CIS plumbing end-to-end
(helper rule, variables, CPE), so Layer C is technically identical to the CIS recipe
with a longer `disableRules` list — with the same "not officially supported" caveat as
STIG.

### 3.4 In-hosted platform scans: one accuracy caveat

Layer A relies on config CRs inside the hosted cluster (`apiservers/cluster`,
`oauths/cluster`, `proxies/cluster`, ...). In HCP these are propagated *from*
`HostedCluster.spec.configuration` by the hosted-cluster-config-operator; users cannot
durably edit them in-cluster. For most rules the mirror is faithful, but the source of
truth is the HostedCluster spec — where a rule's verdict matters for accreditation
(audit profile, TLS profile, OAuth token policy), prefer the Layer E CEL rule against
the HostedCluster over (or in addition to) the in-hosted mirror check. Where the two
disagree, the HostedCluster spec wins and the mirror lag is itself a finding.

## 4. What to run where (deployment matrix)

| Location | Install | Bindings | Purpose |
|---|---|---|---|
| Each hosted cluster | CO with `PLATFORM=HyperShift` (worker-only roles, hosted CPE active) | `ocp4-cis`, `ocp4-stig`, `ocp4-high` (platform) + `ocp4-cis-node`, `ocp4-stig-node`, `ocp4-high-node`, `rhcos4-stig`, `rhcos4-high` | In-cluster half of all three benchmarks; node/OS hardening evidence. Control-plane rules auto-N/A via `ocp4-on-hypershift-hosted`. |
| Management cluster | CO standard install | Per hosted cluster: TailoredProfile extending `ocp4-cis` (supported) and optionally `ocp4-stig`/`ocp4-high` (unsupported) with the two HyperShift variables + `disableRules` | Hosted control-plane configuration (kube-apiserver, etcd, controller-manager, OAuth) |
| Management cluster | same | Plain `ocp4-stig`, `ocp4-high`, `ocp4-cis` + node profiles + `rhcos4-stig`/`rhcos4-high` | The hosting platform's own compliance — part of every hosted cluster's boundary |
| Management cluster | same | TailoredProfile of CEL CustomRules (section 7) | HostedCluster/NodePool-spec checks that no OpenSCAP rule covers on either side |

## 5. Node profiles: what they do and do not give you (Layer B)

Scanning: fully functional. Node scan pods read the host filesystem of hosted-cluster
workers; `rhcos4-stig`/`rhcos4-high` and the `-node` profiles produce accurate results.
Two structural limits:

1. **Worker-only.** `PLATFORM=HyperShift` defaults ScanSettings to the `worker` role.
   All master-node rules (etcd data dir/file permissions, apiserver manifests, admin
   kubeconfigs) are out of scope — the equivalents for the hosted CP are pods and PVCs
   on the management cluster, which no node profile inspects (see section 8, residual
   gap 2).
2. **Remediation transport.** See next section.

## 6. Node remediation on HCP: the NodePool transport

Hosted clusters have no Machine Config Operator; `MachineConfig` objects cannot be
applied in-cluster. The Compliance Operator inside a hosted cluster will still
*create* `ComplianceRemediation` objects from node scan failures (STIG/High node
profiles generate many: audit rules, sshd hardening, sysctls, banners, chrony, USB
guard on rev-4), but applying them there fails — the API is not served.

The supported path is `NodePool.spec.config` on the management cluster:

1. Collect the desired MachineConfigs from the hosted cluster's
   `ComplianceRemediation` objects (`.spec.current.object`).
2. For each, create a ConfigMap in the NodePool's namespace on the management cluster
   with the MachineConfig manifest under the `config` key:

   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: stig-node-mc-bundle
     namespace: clusters
   data:
     config: |
       apiVersion: machineconfiguration.openshift.io/v1
       kind: MachineConfig
       metadata:
         labels:
           machineconfiguration.openshift.io/role: worker
         name: 75-stig-node-hardening
       spec:
         config:
           ignition:
             version: 3.2.0
           ...
   ```

3. Reference it from the NodePool:

   ```yaml
   spec:
     config:
     - name: stig-node-mc-bundle
   ```

4. NodePool rolls the workers (respecting `spec.management.upgradeType` —
   `Replace` recreates nodes, `InPlace` updates them in place); rescan in the hosted
   cluster to confirm the findings clear.

KubeletConfig-type remediations follow the same ConfigMap transport. Since this is a
GitOps-shaped flow, the usbguard lessons apply (`USBGUARD_REMEDIATION_FLOW.md`):
dependency-ordered remediations (package extension before service enablement) cannot be
collapsed into one NodePool rollout unless the systemd unit contents are embedded.

Section 7's `nodepool-has-hardening-config` CustomRule turns "every NodePool carries
the hardening bundle" into a continuously-scanned platform check.

## 7. Closing gaps with CEL CustomRules (Layer E)

### 7.1 Capability summary (verified against the operator source)

- `CustomRule` CR (`compliance.openshift.io/v1alpha1`), namespaced, `scannerType: CEL`,
  `checkType: Platform` only — CEL rules evaluate API state, never node filesystems.
- `inputs[]` bind named variables to arbitrary GVRs (`group`, `apiVersion`, `resource`,
  optional `resourceNamespace`/`resourceName`). List fetches expose `.items`.
- The expression must evaluate to a boolean; `failureReason` becomes the check-result
  instruction text. Results surface as regular `ComplianceCheckResult`s.
- Bound via a TailoredProfile with `enableRules[{kind: CustomRule, name, rationale}]`;
  keep CustomRules in their own TailoredProfile (a scan is either CEL or OpenSCAP,
  never mixed) and bind it with a normal ScanSettingBinding.
- If an input's API type is not served, the result is designed to be NOT-APPLICABLE
  rather than an error (CMP-4483 — an in-development change; verify on your operator
  version). Note the adjacent case observed on v1.9.1: an input the collector lacks
  RBAC for returns ERROR, not NOT-APPLICABLE.
- RBAC: the CEL scanner fetches inputs live from the API server using the
  `api-resource-collector` ServiceAccount in the scan namespace. Reading HyperShift
  resources needs one extra grant on the management cluster:

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: compliance-read-hypershift
  rules:
  - apiGroups: ["hypershift.openshift.io"]
    resources: ["hostedclusters", "nodepools"]
    verbs: ["get", "list"]
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: compliance-read-hypershift
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: compliance-read-hypershift
  subjects:
  - kind: ServiceAccount
    name: api-resource-collector
    namespace: openshift-compliance
  ```

### 7.2 Rule catalog for the identified gaps

All rules below are fleet-wide by design: they assert the condition over **every**
HostedCluster in the `clusters` namespace, so a newly onboarded hosted cluster that
violates the policy immediately fails the scan. Adjust `resourceNamespace` if a
different prefix is used.

**(a) FIPS mode — closes `fips_mode_enabled_on_all_nodes` (STIG SRG-APP-000514, High
SC-13).** `HostedCluster.spec.fips` is immutable and authoritative; the in-cluster rule
reads MachineConfigs that do not exist on HCP.

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: CustomRule
metadata:
  name: hosted-cluster-fips-enabled
  namespace: openshift-compliance
spec:
  title: "Hosted clusters must be created with FIPS mode enabled"
  id: hosted_cluster_fips_enabled
  description: >-
    FIPS mode for a hosted cluster can only be set at creation time via
    HostedCluster.spec.fips and governs the cryptographic modules of both the
    control plane and (via NodePool) the worker nodes.
  failureReason: >-
    One or more HostedCluster resources does not set .spec.fips to true.
    FIPS cannot be enabled after creation; the cluster must be recreated.
  severity: high
  checkType: Platform
  scannerType: CEL
  inputs:
    - name: hcs
      kubernetesInputSpec:
        group: hypershift.openshift.io
        apiVersion: v1beta1
        resource: hostedclusters
        resourceNamespace: clusters
  expression: |
    hcs.items.size() > 0 &&
    hcs.items.all(hc, has(hc.spec.fips) && hc.spec.fips == true)
```

**(b) etcd secret encryption — reinforces `api_server_encryption_provider_cipher`
(STIG/High SC-28).** Already HyperShift-aware in CIS/High via the mgmt tailored scan;
this CEL variant provides the same assurance for STIG (where Layer C is unsupported)
and fleet-wide semantics.

```yaml
  expression: |
    hcs.items.size() > 0 &&
    hcs.items.all(hc,
      has(hc.spec.secretEncryption) &&
      has(hc.spec.secretEncryption.type) &&
      (hc.spec.secretEncryption.type == 'kms' ||
       hc.spec.secretEncryption.type == 'aescbc'))
```

**(c) Audit profile — closes `audit_profile_set` / `audit_logging_enabled` (STIG
SRG-APP-000089ff, High AU-2/AU-12).** STIG requires `WriteRequestBodies`; unset means
`Default`.

```yaml
  expression: |
    hcs.items.size() > 0 &&
    hcs.items.all(hc,
      has(hc.spec.configuration) &&
      has(hc.spec.configuration.apiServer) &&
      has(hc.spec.configuration.apiServer.audit) &&
      has(hc.spec.configuration.apiServer.audit.profile) &&
      hc.spec.configuration.apiServer.audit.profile in
        ['WriteRequestBodies', 'AllRequestBodies'])
```

**(d) API server TLS security profile — closes `api_server_tls_security_profile`(+
`_not_old`, `_custom_min_tls_version`) (High SC-8, STIG SRG-APP-000560).** Unset means
the Intermediate default, which is compliant; explicit `Old` or a weak `Custom` is not.

```yaml
  expression: |
    hcs.items.all(hc,
      !has(hc.spec.configuration) ||
      !has(hc.spec.configuration.apiServer) ||
      !has(hc.spec.configuration.apiServer.tlsSecurityProfile) ||
      (hc.spec.configuration.apiServer.tlsSecurityProfile.type != 'Old' &&
       (hc.spec.configuration.apiServer.tlsSecurityProfile.type != 'Custom' ||
        (has(hc.spec.configuration.apiServer.tlsSecurityProfile.custom.minTLSVersion) &&
         !(hc.spec.configuration.apiServer.tlsSecurityProfile.custom.minTLSVersion in
           ['VersionTLS10', 'VersionTLS11'])))))
```

**(e) OAuth token max age — closes `oauth_or_oauthclient_token_maxage` (STIG requires
<= 8h; the STIG profile sets `var_oauth_token_maxage=8h`).**

```yaml
  expression: |
    hcs.items.size() > 0 &&
    hcs.items.all(hc,
      has(hc.spec.configuration) &&
      has(hc.spec.configuration.oauth) &&
      has(hc.spec.configuration.oauth.tokenConfig) &&
      has(hc.spec.configuration.oauth.tokenConfig.accessTokenMaxAgeSeconds) &&
      hc.spec.configuration.oauth.tokenConfig.accessTokenMaxAgeSeconds <= 28800)
```

**(f) OAuth inactivity timeout — closes `oauth_or_oauthclient_inactivity_timeout`
(STIG SRG-APP-000190, High AC-12).** The field is a duration string; require it to be
set (value policy is organizational, commonly <= 15m for STIG).

```yaml
  expression: |
    hcs.items.size() > 0 &&
    hcs.items.all(hc,
      has(hc.spec.configuration) &&
      has(hc.spec.configuration.oauth) &&
      has(hc.spec.configuration.oauth.tokenConfig) &&
      has(hc.spec.configuration.oauth.tokenConfig.accessTokenInactivityTimeout))
```

**(g) Audit log offload — complements `audit_log_forwarding_enabled`/`_uses_tls`
(High AU-4(1), STIG SRG-APP-000125).** For HCP the hosted KAS audit stream is offloaded
via the HostedCluster audit webhook:

```yaml
  expression: |
    hcs.items.size() > 0 &&
    hcs.items.all(hc,
      has(hc.spec.auditWebhook) && hc.spec.auditWebhook.name != '')
```

(TLS of the webhook endpoint is defined inside the referenced kubeconfig secret —
attest manually or via a second CustomRule on the secret if naming conventions allow.)

**(h) Cluster-wide proxy — closes `cluster_wide_proxy_set` (High, boundary-protection
family)** — assert `hc.spec.configuration.proxy.httpsProxy` is set, same `has()` chain
pattern as (c). Skip if the environment does not require egress proxying.

**(i) NodePool hardening governance — makes section 6 continuously verifiable.**

```yaml
  inputs:
    - name: nps
      kubernetesInputSpec:
        group: hypershift.openshift.io
        apiVersion: v1beta1
        resource: nodepools
        resourceNamespace: clusters
  expression: |
    nps.items.size() > 0 &&
    nps.items.all(np,
      has(np.spec.config) &&
      np.spec.config.exists(c, c.name == 'stig-node-mc-bundle'))
```

**Binding:**

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: hcp-fleet-compliance-cel
  namespace: openshift-compliance
spec:
  title: HCP fleet control-plane compliance (CEL)
  description: HostedCluster/NodePool spec checks closing STIG/High gaps
  enableRules:
    - kind: CustomRule
      name: hosted-cluster-fips-enabled
      rationale: SC-13 / SRG-APP-000514 for hosted control planes and workers
    - kind: CustomRule
      name: hosted-cluster-etcd-encryption
      rationale: SC-28 protection of secrets at rest in the hosted etcd
    # ... remaining rules ...
```

Bind with a standard ScanSettingBinding; results appear as ComplianceCheckResults like
any other scan and are aggregated into the same reporting pipeline.

## 8. Residual gaps (honest list — nothing below is closed by the five layers)

1. **Support statement.** STIG and High management tailored scans work mechanically but
   are not in the supported-profiles list
   ([Configuring the hosted control planes management cluster](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/compliance-operator#co-hcp-mgmt-config_compliance-operator-scans)).
   Until the docs change, findings from Layer C
   for those two profiles are self-supported evidence. Mitigation: file the RFE
   (section 9) and keep the CIS tailored scan (supported) as the anchor.
2. **Hosted CP file-level checks.** Master-node STIG/High rules (etcd data
   directory/file permissions, static pod manifests, PKI file modes) have no HCP
   equivalent: the hosted etcd data lives on PVCs mounted into CP pods. Compensating
   controls: `secretEncryption` (rule b), encrypted storage class for CP PVCs on the
   management cluster, `configure_network_policies_hypershift_hosted` (exists, aware),
   management-cluster node scans (Layer D) for the underlying hosts, and RBAC on the CP
   namespaces. Document these as compensating in the SSP/POA&M.
3. **Hosted KAS audit pipeline TLS.** Rule (g) proves a webhook is configured, not that
   the transport and retention meet AU requirements end to end — that half lives in the
   webhook target and the management cluster's log forwarding, outside any profile's
   automated reach today.
4. **FileIntegrity (AIDE).** `file_integrity_*` rules are `not ocp4-on-hypershift` —
   auto-N/A on the management tailored scan. The File Integrity Operator can still be
   installed separately on both management and hosted clusters; do so and attest.
5. **Manual rules stay manual.** ~21 (CIS) / 11 (STIG) / 25 (High) platform rules are
   MANUAL by design (RBAC judgment calls, SCC usage review, secrets management
   practice). They must be performed against the *hosted* cluster; disabling them in
   Layer C scans avoids double-counting if they are tracked in the hosted cluster's
   attestation.
6. **In-hosted config mirrors.** Where Layer A reads a propagated config CR (section
   3.4), the evidence is one step removed from the source of truth; pair with Layer E.

## 9. Upstream work worth filing (turns workarounds into product)

1. **RFE: extend HyperShift support to `ocp4-stig` and `ocp4-high`.** The mechanism is
   proven and largely inherited: High already gets 57 aware rules via CIS; STIG already
   ships the version-detect helper. The remaining work is per-rule dual-path templating
   for the STIG/High wrong-target sets — the same pattern as the existing 47 CIS rules.
2. **Content: make the near-miss rules aware.** Cheapest wins first:
   `banner_or_login_template_set` (same source as the already-aware
   `oauth_login_template_set`), `audit_profile_set` and `api_server_tls_security_profile`
   (read `HostedCluster.spec.configuration.apiServer`, same source as the already-aware
   `api_server_encryption_provider_cipher`), `oauth_or_oauthclient_*`
   (`.spec.configuration.oauth.tokenConfig`), `fips_mode_enabled_on_all_nodes`
   (`.spec.fips`). Also `oauth_or_oauthclient_inactivity_timeout` for PCI-DSS (noted in
   the companion doc).
3. **Content: CEL rules in ComplianceAsCode.** The rules in section 7 can graduate from
   customer-authored CustomRules into shipped content under
   `applications/openshift/.../cel/`, making them supported and versioned with the
   benchmark.

## 10. Appendix: methodology and numbers

- Rule inventories: `controls/cis_ocp_190/*`, `controls/stig_ocp4.yml`,
  `controls/nist_ocp4.yml` (High = CIS union NIST per
  `products/ocp4/profiles/high-rev-4.profile`, which extends `cis`), node filtering per
  each profile's `filter_rules`.
- HyperShift-aware = rule templates its fetch path with
  `{{.hypershift_cluster}}`/`{{.hypershift_namespace_prefix}}`; platform gating parsed
  from each rule's `platform:` key; automated vs manual from presence of a check
  `template:`/`warnings:` block.
- Headline counts — CIS platform: 47 aware / 4 auto-N/A / 43 wrong-target of 94.
  STIG platform: 6 / 4 / 38 of 48. High platform: 57 / 6 / 71 of 134.
- Operator facts verified in source: HyperShift platform defaults
  (`cmd/manager/operator.go:100-155`), CustomRule API and validation
  (`pkg/apis/compliance/v1alpha1/customrule_types.go`), CEL scanner container and
  ServiceAccount (`pkg/controller/compliancescan/scan.go:355-400,487`), CEL
  input-not-served -> NOT-APPLICABLE (commit `87aff2a96`, CMP-4483), TailoredProfile
  CustomRule references (`tailoredprofile_types.go:20`), sample CustomRules
  (`config/samples/custom-rules/openshift-virtualization/`).
