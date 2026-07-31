# Full Rule Coverage Matrix: CIS / STIG / High on Hosted Control Planes

Generated 2026-07-31 from ComplianceAsCode content (CIS v1.9.0, STIG v2r3, NIST rev-4)
merged with LIVE results from BOTH validated scan locations on cluster
`ci-ln-b6zqd5k-76ef8` (CO v1.9.1 in both places):

- **Mgmt tailored scans** — TailoredProfiles with HyperShift variables against
  HostedCluster `hcp-demo` (none-platform, CP-only) from the management cluster.
- **In-hosted tailored scans** — CO installed inside AWS HostedCluster `hcp-aws`
  (4.20.32, 2 workers) via OLM (Subscription needs `nodeSelector` worker override —
  the CSV pins to masters which do not exist in hosted clusters). Control-plane rules
  are disabled by TailoredProfile because the `ocp4-on-hypershift-hosted` CPE never
  fires (operator passes `--platform=HyperShift` on an initContainer; the OVAL check
  reads `.spec.containers[:]` only). Without the workaround those rules false-FAIL.

Column key: A/M = automated/manual. `-` in a live column = no result (rule disabled,
NOT-APPLICABLE, or not selected in that scan). Node-platform rules are excluded from
the tables; they run via node profiles inside the hosted cluster — live validated:
`ocp4-cis-node-worker` 57 PASS (COMPLIANT), `ocp4-stig-node-worker` 2 PASS / 1 FAIL,
`rhcos4-stig-worker` 17 PASS / 98 FAIL / 1 MANUAL (unhardened RHCOS, expected).

## 1. Layer contributions and live scan totals

| Scan | Where | Result |
|---|---|---|
| `hypershift-cis-hcp-demo` (mgmt) | hosted CP config | 49 PASS / 21 MANUAL / 7 FAIL |
| `hypershift-stig-hcp-demo` (mgmt) | hosted CP config | 2 PASS / 11 MANUAL / 4 FAIL |
| `hypershift-high-hcp-demo` (mgmt) | hosted CP config | 43 PASS / 23 MANUAL / 7 FAIL |
| `hcp-cel-workarounds` (mgmt, CEL) | HostedCluster/NodePool spec + etcd env | 8 PASS / 6 FAIL |
| `hosted-cis-tailored` (in hcp-aws) | in-cluster half | 14 PASS / 21 MANUAL / 8 FAIL |
| `hosted-stig-tailored` (in hcp-aws) | in-cluster half | 14 PASS / 11 MANUAL / 19 FAIL |
| `hosted-high-tailored` (in hcp-aws) | in-cluster half | 28 PASS / 23 MANUAL / 24 FAIL |
| node scans (in hcp-aws) | worker nodes | see above |

Combined coverage: every automated platform rule of all three benchmarks now has
exactly one authoritative source (Mgmt scan, Hosted scan, or CEL) except the two
`no-unsupported-config-overrides` rules (SSP statement) and SDN-gated rules (N/A on
OVN). Manual rules are attested against the hosted cluster once.


### 2. ocp4-cis platform profile

| Rule | A/M | Mgmt tailored scan | Live mgmt | In-hosted tailored scan | Live in-hosted | Recommended source |
|---|---|---|---|---|---|---|
| `accounts_restrict_service_account_tokens` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `accounts_unique_service_account` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `api_server_admission_control_plugin_alwaysadmit` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_alwayspullimages` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_namespacelifecycle` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_noderestriction` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_scc` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_service_account` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_anonymous_auth` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `api_server_audit_log_maxbackup` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_audit_log_maxsize` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_audit_log_path` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_auth_mode_no_aa` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_auth_mode_rbac` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_bind_address` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_client_ca` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_encryption_provider_cipher` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_etcd_ca` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_etcd_cert` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_etcd_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_https_for_kubelet_conn` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_insecure_bind_address` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_kube_no_unsupported_config_overrides` | A | wrong-target; architectural N/A | PASS | disabled in-hosted (CP rule) | - | SSP statement |
| `api_server_kubelet_certificate_authority` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_kubelet_client_cert` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_kubelet_client_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_no_unsupported_config_overrides` | A | wrong-target; architectural N/A | PASS | disabled in-hosted (CP rule) | - | SSP statement |
| `api_server_oauth_https_serving_cert` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `api_server_openshift_https_serving_cert` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `api_server_profiling_protected_by_rbac` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `api_server_request_timeout` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_service_account_lookup` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_service_account_public_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_tls_cert` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_tls_private_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_tls_security_profile_custom_min_tls_version` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | CEL + Hosted |
| `api_server_tls_security_profile_not_old` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | CEL + Hosted |
| `audit_log_forwarding_enabled` | A | auto N/A | - | disabled in-hosted (CP rule) | - | Hosted scan |
| `audit_log_forwarding_webhook` | A | CORRECT hosted-CP data (aware) | FAIL | N/A (mgmt-side rule) | - | Mgmt scan |
| `audit_logging_enabled` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | CEL + Hosted |
| `audit_profile_set` | A | disabled -> CEL `hcp-audit-profile` | - | covered in-hosted | FAIL | CEL |
| `configure_network_policies` | A | auto N/A | - | covered in-hosted | PASS | Hosted scan |
| `configure_network_policies_hypershift_hosted` | A | CORRECT hosted-CP data (aware) | PASS | N/A (mgmt-side rule) | - | Mgmt scan |
| `configure_network_policies_namespaces` | A | auto N/A | - | covered in-hosted | FAIL | Hosted scan |
| `controller_service_account_ca` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `controller_service_account_private_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `controller_use_service_account` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `etcd_auto_tls` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `etcd_cert_file` | A | disabled -> CEL `hcp-etcd-cert-file` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_client_cert_auth` | A | disabled -> CEL `hcp-etcd-client-cert-auth` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_key_file` | A | disabled -> CEL `hcp-etcd-key-file` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_peer_auto_tls` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `etcd_peer_cert_file` | A | disabled -> CEL `hcp-etcd-peer-cert-file` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_peer_client_cert_auth` | A | disabled -> CEL `hcp-etcd-peer-client-cert-auth` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_peer_key_file` | A | disabled -> CEL `hcp-etcd-peer-key-file` | - | disabled in-hosted (CP rule) | - | CEL |
| `file_groupowner_proxy_kubeconfig` | M | MANUAL | - | MANUAL | - | Manual |
| `file_owner_proxy_kubeconfig` | M | MANUAL | - | MANUAL | - | Manual |
| `file_permissions_proxy_kubeconfig` | A | N/A on OVN | - | N/A on OVN | - | - |
| `general_apply_scc` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `general_default_namespace_use` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `general_default_seccomp_profile` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `general_namespaces_in_use` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `idp_is_configured` | A | CORRECT hosted-CP data (aware) | FAIL | runs on HostedCluster-spec mirror | FAIL | Mgmt scan |
| `ingress_controller_tls_cipher_suites` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `kubeadmin_removed` | A | auto N/A | - | covered in-hosted | FAIL | Hosted scan |
| `kubelet_configure_tls_cert` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `kubelet_configure_tls_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `kubelet_disable_readonly_port` | A | CORRECT hosted-CP data (aware) | PASS | runs on HostedCluster-spec mirror | FAIL | Mgmt scan |
| `ocp_allowed_registries` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `ocp_allowed_registries_for_import` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `ocp_api_server_audit_log_maxbackup` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `ocp_api_server_audit_log_maxsize` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `ocp_insecure_allowed_registries_for_import` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `ocp_insecure_registries` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `openshift_api_server_audit_log_path` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `rbac_debug_role_protects_pprof` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `rbac_least_privilege` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_limit_cluster_admin` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_limit_secrets_access` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_pod_creation_access` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_wildcard_use` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_drop_container_capabilities` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_container_allowed_capabilities` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `scc_limit_ipc_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_net_raw_capability` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_network_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_privilege_escalation` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_privileged_containers` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_process_id_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_root_containers` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scheduler_profiling_protected_by_rbac` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `scheduler_service_protected_by_rbac` | A | WRONG-TARGET (reads mgmt) | PASS | covered in-hosted | PASS | Hosted scan |
| `secrets_consider_external_storage` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `secrets_no_environment_variables` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |

Platform rules listed: 94


### 3. ocp4-stig platform profile

| Rule | A/M | Mgmt tailored scan | Live mgmt | In-hosted tailored scan | Live in-hosted | Recommended source |
|---|---|---|---|---|---|---|
| `api_server_encryption_provider_cipher` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_tls_security_profile` | A | disabled -> CEL `hcp-api-tls-security-profile` | - | covered in-hosted | PASS | CEL |
| `audit_error_alert_exists` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `audit_log_forwarding_enabled` | A | auto N/A | - | disabled in-hosted (CP rule) | - | Hosted scan |
| `audit_log_forwarding_uses_tls` | A | disabled -> CEL `hcp-audit-webhook (existence only)` | - | covered in-hosted | FAIL | CEL |
| `audit_profile_set` | A | disabled -> CEL `hcp-audit-profile` | - | covered in-hosted | FAIL | CEL |
| `classification_banner` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `cluster_logging_operator_exist` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `cluster_version_operator_exists` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `cluster_version_operator_verify_integrity` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `configure_network_policies` | A | auto N/A | - | covered in-hosted | PASS | Hosted scan |
| `configure_network_policies_namespaces` | A | auto N/A | - | covered in-hosted | FAIL | Hosted scan |
| `container_security_operator_exists` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `fips_mode_enabled_on_all_nodes` | A | disabled -> CEL `hcp-fips-enabled` | - | covered in-hosted | FAIL | CEL |
| `idp_is_configured` | A | CORRECT hosted-CP data (aware) | FAIL | runs on HostedCluster-spec mirror | FAIL | Mgmt scan |
| `image_pruner_active` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `imagestream_sets_schedule` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `ingress_controller_tls_security_profile` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `kubeadmin_removed` | A | auto N/A | - | covered in-hosted | FAIL | Hosted scan |
| `oauth_login_template_set` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `oauth_logout_url_set` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `oauth_or_oauthclient_inactivity_timeout` | A | disabled -> CEL `hcp-oauth-inactivity-timeout` | - | covered in-hosted | FAIL | CEL |
| `oauth_or_oauthclient_token_maxage` | A | disabled -> CEL `hcp-oauth-token-maxage` | - | covered in-hosted | FAIL | CEL |
| `oauth_provider_selection_set` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `ocp_allowed_registries` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `ocp_allowed_registries_for_import` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `ocp_idp_no_htpasswd` | A | CORRECT hosted-CP data (aware) | PASS | runs on HostedCluster-spec mirror | PASS | Mgmt scan |
| `ocp_insecure_allowed_registries_for_import` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `ocp_insecure_registries` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `ocp_no_ldap_insecure` | A | CORRECT hosted-CP data (aware) | PASS | runs on HostedCluster-spec mirror | PASS | Mgmt scan |
| `openshift_motd_exists` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `project_config_and_template_network_policy` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `project_config_and_template_resource_quota` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `rbac_least_privilege` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_logging_del` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_logging_mod` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_logging_view` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `resource_requests_quota_per_project` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `routes_rate_limit` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `scansettingbinding_exists` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `scansettings_have_schedule` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `scc_limit_host_dir_volume_plugin` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_host_ports` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_ipc_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_network_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_privileged_containers` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_process_id_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_root_containers` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |

Platform rules listed: 48


### 4. ocp4-high platform profile

| Rule | A/M | Mgmt tailored scan | Live mgmt | In-hosted tailored scan | Live in-hosted | Recommended source |
|---|---|---|---|---|---|---|
| `accounts_restrict_service_account_tokens` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `accounts_unique_service_account` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `alert_receiver_configured` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `api_server_admission_control_plugin_alwaysadmit` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_alwayspullimages` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_namespacelifecycle` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_noderestriction` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_scc` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_securitycontextdeny` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_admission_control_plugin_service_account` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_anonymous_auth` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `api_server_api_priority_flowschema_catch_all` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `api_server_audit_log_maxbackup` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_audit_log_maxsize` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_audit_log_path` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_auth_mode_no_aa` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_auth_mode_node` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_auth_mode_rbac` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_basic_auth` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_bind_address` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_client_ca` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_encryption_provider_cipher` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_etcd_ca` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_etcd_cert` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_etcd_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_https_for_kubelet_conn` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_insecure_bind_address` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_kube_no_unsupported_config_overrides` | A | disabled (wrong-target) | - | disabled in-hosted (CP rule) | - | SSP statement |
| `api_server_kubelet_certificate_authority` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_kubelet_client_cert` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_kubelet_client_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_no_adm_ctrl_plugins_disabled` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_no_unsupported_config_overrides` | A | disabled (wrong-target) | - | disabled in-hosted (CP rule) | - | SSP statement |
| `api_server_oauth_https_serving_cert` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `api_server_openshift_https_serving_cert` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `api_server_profiling_protected_by_rbac` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `api_server_request_timeout` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_service_account_lookup` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_service_account_public_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_tls_cert` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_tls_private_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `api_server_tls_security_profile` | A | disabled -> CEL `hcp-api-tls-security-profile` | - | covered in-hosted | PASS | CEL |
| `api_server_tls_security_profile_custom_min_tls_version` | A | disabled -> CEL `hcp-api-tls-security-profile` | - | covered in-hosted | PASS | CEL |
| `api_server_tls_security_profile_not_old` | A | disabled -> CEL `hcp-api-tls-security-profile` | - | covered in-hosted | PASS | CEL |
| `api_server_token_auth` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `audit_error_alert_exists` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `audit_log_forwarding_enabled` | A | auto N/A | - | disabled in-hosted (CP rule) | - | Hosted scan |
| `audit_log_forwarding_uses_tls` | A | disabled -> CEL `hcp-audit-webhook (existence only)` | - | covered in-hosted | FAIL | CEL |
| `audit_log_forwarding_webhook` | A | CORRECT hosted-CP data (aware) | FAIL | N/A (mgmt-side rule) | - | Mgmt scan |
| `audit_logging_enabled` | A | disabled -> CEL `hcp-audit-profile` | - | covered in-hosted | PASS | CEL |
| `audit_profile_set` | A | disabled -> CEL `hcp-audit-profile` | - | covered in-hosted | FAIL | CEL |
| `banner_or_login_template_set` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `cluster_logging_operator_exist` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `cluster_version_operator_exists` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `cluster_version_operator_verify_integrity` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `cluster_wide_proxy_set` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `compliance_notification_enabled` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `configure_network_policies` | A | auto N/A | - | covered in-hosted | PASS | Hosted scan |
| `configure_network_policies_hypershift_hosted` | A | CORRECT hosted-CP data (aware) | PASS | N/A (mgmt-side rule) | - | Mgmt scan |
| `configure_network_policies_namespaces` | A | auto N/A | - | covered in-hosted | FAIL | Hosted scan |
| `controller_insecure_port_disabled` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `controller_rotate_kubelet_server_certs` | A | CORRECT hosted-CP data (aware) | - | disabled in-hosted (CP rule) | - | Mgmt scan |
| `controller_secure_port` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `controller_service_account_ca` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `controller_service_account_private_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `controller_use_service_account` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `default_ingress_ca_replaced` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `etcd_auto_tls` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `etcd_cert_file` | A | disabled -> CEL `hcp-etcd-cert-file` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_client_cert_auth` | A | disabled -> CEL `hcp-etcd-client-cert-auth` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_key_file` | A | disabled -> CEL `hcp-etcd-key-file` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_peer_auto_tls` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `etcd_peer_cert_file` | A | disabled -> CEL `hcp-etcd-peer-cert-file` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_peer_client_cert_auth` | A | disabled -> CEL `hcp-etcd-peer-client-cert-auth` | - | disabled in-hosted (CP rule) | - | CEL |
| `etcd_peer_key_file` | A | disabled -> CEL `hcp-etcd-peer-key-file` | - | disabled in-hosted (CP rule) | - | CEL |
| `file_groupowner_proxy_kubeconfig` | M | MANUAL | - | MANUAL | - | Manual |
| `file_integrity_exists` | A | auto N/A | - | covered in-hosted | FAIL | Hosted scan |
| `file_integrity_notification_enabled` | A | auto N/A | - | covered in-hosted | FAIL | Hosted scan |
| `file_owner_proxy_kubeconfig` | M | MANUAL | - | MANUAL | - | Manual |
| `file_permissions_proxy_kubeconfig` | A | N/A on OVN | - | N/A on OVN | - | - |
| `fips_mode_enabled_on_all_nodes` | A | disabled -> CEL `hcp-fips-enabled` | - | covered in-hosted | FAIL | CEL |
| `general_apply_scc` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `general_configure_imagepolicywebhook` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `general_default_namespace_use` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `general_default_seccomp_profile` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `general_namespaces_in_use` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `gitops_operator_exists` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `idp_is_configured` | A | CORRECT hosted-CP data (aware) | FAIL | runs on HostedCluster-spec mirror | FAIL | Mgmt scan |
| `ingress_controller_certificate` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `ingress_controller_tls_cipher_suites` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `ingress_controller_tls_security_profile` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `kubeadmin_removed` | A | auto N/A | - | covered in-hosted | FAIL | Hosted scan |
| `kubelet_configure_tls_cert` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `kubelet_configure_tls_key` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `kubelet_disable_readonly_port` | A | CORRECT hosted-CP data (aware) | PASS | runs on HostedCluster-spec mirror | FAIL | Mgmt scan |
| `oauth_or_oauthclient_inactivity_timeout` | A | disabled -> CEL `hcp-oauth-inactivity-timeout` | - | covered in-hosted | FAIL | CEL |
| `oauth_or_oauthclient_token_maxage` | A | disabled -> CEL `hcp-oauth-token-maxage` | - | covered in-hosted | FAIL | CEL |
| `ocp_allowed_registries` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `ocp_allowed_registries_for_import` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `ocp_api_server_audit_log_maxbackup` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `ocp_api_server_audit_log_maxsize` | A | CORRECT hosted-CP data (aware) | FAIL | disabled in-hosted (CP rule) | - | Mgmt scan |
| `ocp_idp_no_htpasswd` | A | CORRECT hosted-CP data (aware) | PASS | runs on HostedCluster-spec mirror | PASS | Mgmt scan |
| `ocp_insecure_allowed_registries_for_import` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `ocp_insecure_registries` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `ocp_no_ldap_insecure` | A | CORRECT hosted-CP data (aware) | PASS | runs on HostedCluster-spec mirror | PASS | Mgmt scan |
| `openshift_api_server_audit_log_path` | A | CORRECT hosted-CP data (aware) | PASS | disabled in-hosted (CP rule) | - | Mgmt scan |
| `openshift_motd_exists` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `rbac_debug_role_protects_pprof` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `rbac_least_privilege` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_limit_cluster_admin` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_limit_secrets_access` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_pod_creation_access` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `rbac_wildcard_use` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `resource_requests_limits_in_daemonset` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `resource_requests_limits_in_deployment` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `resource_requests_limits_in_statefulset` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `resource_requests_quota` | A | disabled (wrong-target) | - | covered in-hosted | FAIL | Hosted scan |
| `route_ip_whitelist` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `routes_protected_by_tls` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `routes_rate_limit` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `scansettingbinding_exists` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `scc_drop_container_capabilities` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_container_allowed_capabilities` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `scc_limit_ipc_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_net_raw_capability` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_network_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_privilege_escalation` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_privileged_containers` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_process_id_namespace` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scc_limit_root_containers` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `scheduler_profiling_protected_by_rbac` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `scheduler_service_protected_by_rbac` | A | disabled (wrong-target) | - | covered in-hosted | PASS | Hosted scan |
| `secrets_consider_external_storage` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |
| `secrets_no_environment_variables` | M | MANUAL | MANUAL | MANUAL | MANUAL | Manual |

Platform rules listed: 134
