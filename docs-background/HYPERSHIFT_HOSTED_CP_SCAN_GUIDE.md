# Scanning Hosted Control Planes (HyperShift) with the Compliance Operator

**Audience:** customers and support engineers working with the Compliance Operator on
self-managed Hosted Control Planes (HyperShift) management clusters.

**Scope:** explains how the `ocp4-cis` and `ocp4-pci-dss` management-cluster scan works
internally, which rules genuinely assess the *hosted* cluster, which rules silently assess
the *management* cluster instead, and which rules you should disable (and why).

Verified against ComplianceAsCode/content (CIS benchmark v1.9.0 controls, PCI-DSS v4.0
controls) and the Compliance Operator source (`cmd/manager/scap.go`,
`pkg/utils/parse_arf_result.go`, `pkg/utils/xml2text.go`).

---

## 1. Background: where things live in a HyperShift topology

In a Hosted Control Planes deployment there are two clusters involved, and the control
plane of the hosted cluster does not run inside the hosted cluster:

```
+--------------------------------------------------------------+
| Management cluster                                           |
|                                                              |
|  namespace: clusters                <- HostedCluster CRs     |
|  namespace: clusters-mycluster      <- hosted CONTROL PLANE  |
|     kube-apiserver pods (kas-config configmap)               |
|     etcd pods                                                |
|     kube-controller-manager pods                             |
|     openshift-apiserver pods                                 |
|                                                              |
|  namespace: openshift-kube-apiserver   <- MGMT cluster's own |
|  namespace: openshift-etcd                control plane      |
|  cluster-scoped: oauths/cluster, apiservers/cluster, ...     |
+--------------------------------------------------------------+

+--------------------------------------------------------------+
| Hosted cluster ("mycluster")                                 |
|   worker nodes, workloads, RBAC, SCCs, routes, registries    |
|   (NO control-plane pods here)                               |
+--------------------------------------------------------------+
```

A single Compliance Operator scan can only talk to the API server of the cluster it is
installed in. So a scan running on the management cluster can see:

- the management cluster's own resources (its oauth config, its RBAC, its SCCs, ...);
- the hosted control plane's pods and configmaps, because they are ordinary namespaced
  objects in `clusters-mycluster` on the management cluster;
- the `HostedCluster` custom resource, which carries part of the hosted cluster's
  configuration (for example `spec.configuration.oauth`).

It can NOT see resources that exist only inside the hosted cluster (its RBAC, SCCs,
namespaces, routes, image registry configuration, and so on). That asymmetry is the root
cause of everything in section 4.

## 2. The two supported scan points

For full coverage of a hosted cluster you need two scans:

1. **Management-cluster scan (this document).** A `TailoredProfile` extending `ocp4-cis`
   or `ocp4-pci-dss` with the two HyperShift variables set. It covers the hosted
   *control plane* (kube-apiserver, etcd, controller-manager, openshift-apiserver
   configuration) by reading the pods/configmaps in the `<prefix>-<name>` namespace.

2. **Hosted-cluster scan (optional but recommended).** The Compliance Operator installed
   *inside* the hosted cluster (built/deployed with `PLATFORM=hypershift`, which passes
   `--platform=HyperShift` to the operator). There, all in-cluster rules (RBAC, SCC,
   registries, namespaces, ...) evaluate correctly, and the control-plane rules are
   automatically marked NOT-APPLICABLE because the control plane is not present.

Only `ocp4-cis` and `ocp4-pci-dss` (platform profiles) are supported for the
management-cluster scan. Node profiles (`ocp4-cis-node`, `ocp4-pci-dss-node`) run against
node filesystems and cannot target another cluster's nodes from the management cluster.

## 3. How the management-cluster scan works, step by step

### 3.1 The TailoredProfile sets two variables

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: hypershift-cis-mycluster
  namespace: openshift-compliance
spec:
  extends: ocp4-cis
  title: CIS scan of hosted control plane "mycluster"
  setValues:
  - name: ocp4-hypershift-cluster
    value: mycluster            # NAME column of `oc get hostedcluster -A`
    rationale: hosted cluster to scan
  - name: ocp4-hypershift-namespace-prefix
    value: clusters             # NAMESPACE column of `oc get hostedcluster -A`
    rationale: namespace that holds the HostedCluster CR
```

These map to two content variables defined in
`applications/openshift/hypershift_cluster.var` and
`applications/openshift/hypershift_namespace_prefix.var`:

| Variable | Default | Meaning |
|---|---|---|
| `hypershift_cluster` | `"None"` (literal string) | hosted cluster name; `"None"` means "this is not a HyperShift scan" |
| `hypershift_namespace_prefix` | `clusters` | namespace holding the `HostedCluster` CR; the control plane lives in `<prefix>-<name>` |

NOTE: the default really is the four-character string `None` in the built datastream
(the empty YAML default is serialized as Python's `None`). A hosted cluster literally
named "None" would break detection; do not do that.

### 3.2 Rules carry templated API paths; the operator resolves them

Every automated platform rule embeds the API endpoint it needs in an XCCDF `warning`
element (`<code class="ocp-api-endpoint">...`). HyperShift-aware rules embed a Go-template
conditional instead of a fixed path. Example from
`applications/openshift/api-server/api_server_client_ca/rule.yml`:

```
default path:    /api/v1/namespaces/openshift-kube-apiserver/configmaps/config
hypershift path: /api/v1/namespaces/{{.hypershift_namespace_prefix}}-{{.hypershift_cluster}}/configmaps/kas-config
selector:        {{if ne .hypershift_cluster "None"}} <hypershift path> {{else}} <default path> {{end}}
```

Before the scan runs, the operator's api-resource-collector
(`FigureResources` in `cmd/manager/scap.go`) walks the selected rules, collects all XCCDF
variable values (TailoredProfile values override datastream defaults, see
`getResourcePaths`), and renders each path with Go `text/template`
(`RenderValues` in `pkg/utils/xml2text.go`). With `ocp4-hypershift-cluster=mycluster` the
condition is true, so the collector fetches
`/api/v1/namespaces/clusters-mycluster/configmaps/kas-config` — the *hosted* cluster's
kube-apiserver configuration — and stores it where the OpenSCAP check expects it.

The same pattern covers the different control-plane layouts. On a standalone cluster the
config lives in dedicated namespaces/configmaps; on HyperShift it lives in the hosted
control plane namespace, sometimes as pod arguments instead of configmaps:

| Component | Standalone source | HyperShift source (in `<prefix>-<name>`) |
|---|---|---|
| kube-apiserver | `openshift-kube-apiserver/configmaps/config` | `configmaps/kas-config` |
| openshift-apiserver | `openshift-apiserver/configmaps/config` | `configmaps/openshift-apiserver` |
| etcd | `openshift-etcd/configmaps/etcd-pod` | `pods?labelSelector=app=etcd` (container args) |
| kube-controller-manager | `openshift-kube-controller-manager/configmaps/config` | `pods?labelSelector=app=kube-controller-manager` |
| OAuth/IdP config | `oauths/cluster` | `hostedclusters/<name>` -> `.spec.configuration.oauth` |

### 3.3 Platform (CPE) detection selects the right rule set

The content defines two HyperShift-specific platforms
(`shared/applicability/ocp4-on-hypershift.yml`, `ocp4-on-hypershift-hosted.yml`,
OVAL logic in `shared/applicability/oval/installed_app_is_ocp4.xml`):

- **`ocp4-on-hypershift`** ("I am a management cluster scanning a hosted control
  plane"): true when the helper rule `version_detect_in_hypershift` succeeded. That
  helper only fetches the `HostedCluster` object when `hypershift_cluster != "None"`, so
  in practice this platform is ON exactly when your TailoredProfile sets the variables
  and the named HostedCluster exists.
- **`ocp4-on-hypershift-hosted`** ("I am a hosted cluster"): true when the scanner pod's
  own manifest contains `--platform=HyperShift` (the operator always dumps its own pod
  manifest for this check; `cmd/manager/scap.go:186-189`).

Rules use these platforms to opt in or out per scenario:

- `platform: not ocp4-on-hypershift` — rule is automatically NOT-APPLICABLE on the
  management-cluster scan (example: `kubeadmin_removed`, because it would find the
  *management* cluster's kubeadmin secret and say nothing about the hosted cluster).
- `platform: not ocp4-on-hypershift-hosted` — rule is NOT-APPLICABLE when scanning from
  inside a hosted cluster (all control-plane config rules, since the control plane is not
  there).
- `platform: ocp4-on-hypershift` — rule only exists for the management-cluster scan
  (example: `configure_network_policies_hypershift_hosted`, which checks NetworkPolicies
  *in the hosted control plane namespace* on the management cluster).

### 3.4 Scan flow summary

```
TailoredProfile (extends ocp4-cis, sets 2 variables)
        |
        v
api-resource-collector (init container of the scanner pod)
  - reads rule warnings from the datastream
  - substitutes {{.hypershift_cluster}} / {{.hypershift_namespace_prefix}}
  - GETs each resolved path from the MANAGEMENT cluster API
  - writes results to /kubernetes-api-resources/...
        |
        v
OpenSCAP evaluates rules against the dumped files
  - CPE ocp4-on-hypershift = true  -> hypershift-gated rules activate,
    "not ocp4-on-hypershift" rules become NOT-APPLICABLE
        |
        v
ComplianceCheckResults (PASS / FAIL / MANUAL / NOT-APPLICABLE)
```

## 4. The gap: rules that assess the management cluster, not the hosted cluster

Only rules with the templated dual path actually follow the HyperShift variables. Every
other automated platform rule still queries the management cluster's API and therefore
reports on the **management cluster's** configuration, while appearing in a report that
claims to describe the hosted cluster. The result is not an error — it is a PASS or FAIL
about the wrong cluster.

The full per-rule classification (derived from the content sources; see Appendix for the
method):

### 4.1 ocp4-cis (CIS v1.9.0, 197 rules in the benchmark)

| Category | Count | Behavior on the management scan |
|---|---|---|
| HyperShift-aware (dual-path) | 47 | Correct: read hosted control plane objects |
| Auto NOT-APPLICABLE (`not ocp4-on-hypershift`) | 4 | Correctly suppressed |
| Node-scoped | 103 | Not in the platform profile at all |
| **Wrong-target, automated** | **19** | **PASS/FAIL reflects the management cluster — disable these** |
| Wrong-target, manual | 21 | Always MANUAL; instructions target the wrong cluster |
| SDN-gated leftovers | 3 | NOT-APPLICABLE on OVN-Kubernetes clusters |

**Wrong-target automated rules to disable in the TailoredProfile** (names as they appear
in the cluster, i.e. content rule id with `ocp4-` prefix and dashes):

| Rule (cluster name) | What it actually reads on the mgmt scan |
|---|---|
| `ocp4-api-server-anonymous-auth` | mgmt `clusterrolebindings` |
| `ocp4-api-server-kube-no-unsupported-config-overrides` | mgmt `kubeapiservers` operator CR |
| `ocp4-api-server-no-unsupported-config-overrides` | mgmt `openshiftapiservers` operator CR |
| `ocp4-api-server-oauth-https-serving-cert` | mgmt `apiservers/cluster` |
| `ocp4-api-server-openshift-https-serving-cert` | mgmt `apiservers/cluster` |
| `ocp4-api-server-profiling-protected-by-rbac` | mgmt `clusterroles/cluster-debugger` |
| `ocp4-api-server-tls-security-profile-custom-min-tls-version` | mgmt `apiservers/cluster` |
| `ocp4-api-server-tls-security-profile-not-old` | mgmt `apiservers/cluster` |
| `ocp4-audit-logging-enabled` | mgmt `apiservers/cluster` audit profile |
| `ocp4-audit-profile-set` | mgmt `apiservers/cluster` audit profile |
| `ocp4-ingress-controller-tls-cipher-suites` | mgmt default `ingresscontroller` |
| `ocp4-ocp-allowed-registries` | mgmt `images/cluster` |
| `ocp4-ocp-allowed-registries-for-import` | mgmt `images/cluster` |
| `ocp4-ocp-insecure-allowed-registries-for-import` | mgmt `images/cluster` |
| `ocp4-ocp-insecure-registries` | mgmt `images/cluster` |
| `ocp4-rbac-debug-role-protects-pprof` | mgmt `clusterroles/cluster-debugger` |
| `ocp4-scc-limit-container-allowed-capabilities` | mgmt `securitycontextconstraints` |
| `ocp4-scheduler-profiling-protected-by-rbac` | mgmt `clusterroles/cluster-debugger` |
| `ocp4-scheduler-service-protected-by-rbac` | mgmt `clusterroles/cluster-debugger` |

**Wrong-target manual rules** (these always return MANUAL, so they do not produce
misleading PASS/FAIL; but their instructions must be performed against the *hosted*
cluster, not the management cluster — disabling them on the management scan and
attesting them on the hosted-cluster scan avoids double counting):

`ocp4-accounts-restrict-service-account-tokens`, `ocp4-accounts-unique-service-account`,
`ocp4-general-apply-scc`, `ocp4-general-default-namespace-use`,
`ocp4-general-default-seccomp-profile`, `ocp4-general-namespaces-in-use`,
`ocp4-rbac-least-privilege`, `ocp4-rbac-limit-cluster-admin`,
`ocp4-rbac-limit-secrets-access`, `ocp4-rbac-pod-creation-access`,
`ocp4-rbac-wildcard-use`, `ocp4-scc-drop-container-capabilities`,
`ocp4-scc-limit-ipc-namespace`, `ocp4-scc-limit-net-raw-capability`,
`ocp4-scc-limit-network-namespace`, `ocp4-scc-limit-privilege-escalation`,
`ocp4-scc-limit-privileged-containers`, `ocp4-scc-limit-process-id-namespace`,
`ocp4-scc-limit-root-containers`, `ocp4-secrets-consider-external-storage`,
`ocp4-secrets-no-environment-variables`

(SDN-gated: `ocp4-file-permissions-proxy-kubeconfig`, `ocp4-file-owner-proxy-kubeconfig`,
`ocp4-file-groupowner-proxy-kubeconfig` — NOT-APPLICABLE on OVN-Kubernetes.)

**Automatically suppressed — no action needed:** `ocp4-kubeadmin-removed`,
`ocp4-configure-network-policies`, `ocp4-configure-network-policies-namespaces`,
`ocp4-audit-log-forwarding-enabled` (replaced on HyperShift by
`ocp4-audit-log-forwarding-webhook`, which checks the HostedCluster/ClusterLogForwarder
instead).

### 4.2 ocp4-pci-dss (PCI-DSS v4.0, 67 rules in the benchmark)

| Category | Count |
|---|---|
| HyperShift-aware (dual-path) | 26 |
| Auto NOT-APPLICABLE (`not ocp4-on-hypershift`) | 5 (`kubeadmin_removed`, `configure_network_policies`, `configure_network_policies_namespaces`, `file_integrity_exists`, `file_integrity_notification_enabled`) |
| Node-scoped | 15 |
| **Wrong-target, automated** | **19** |
| Wrong-target, manual | 2 (`alert_receiver_configured`, `rbac_limit_cluster_admin`) |

**Wrong-target automated rules to disable:**

| Rule (cluster name) | What it actually reads on the mgmt scan |
|---|---|
| `ocp4-acs-sensor-exists` | mgmt deployments (looks for ACS sensor on mgmt) |
| `ocp4-api-server-oauth-https-serving-cert` | mgmt `apiservers/cluster` |
| `ocp4-api-server-openshift-https-serving-cert` | mgmt `apiservers/cluster` |
| `ocp4-api-server-tls-security-profile` | mgmt `apiservers/cluster` |
| `ocp4-audit-error-alert-exists` | mgmt `prometheusrules` |
| `ocp4-audit-logging-enabled` | mgmt `apiservers/cluster` |
| `ocp4-audit-profile-set` | mgmt `apiservers/cluster` |
| `ocp4-container-security-operator-exists` | mgmt operator subscription |
| `ocp4-ingress-controller-certificate` | mgmt default `ingresscontroller` |
| `ocp4-ingress-controller-tls-security-profile` | mgmt default `ingresscontroller` |
| `ocp4-machine-volume-encrypted` | mgmt `machinesets`/`machineconfigs` (hosted workers use NodePools instead) |
| `ocp4-oauth-or-oauthclient-inactivity-timeout` | mgmt `oauths/cluster` + `oauthclients` |
| `ocp4-rbac-cluster-roles-defined` | mgmt `clusterroles` |
| `ocp4-rbac-roles-defined` | mgmt `roles` |
| `ocp4-routes-protected-by-tls` | mgmt `routes` |
| `ocp4-scansettingbinding-exists` | mgmt `scansettingbindings` (trivially PASS: the scan itself is one) |
| `ocp4-security-profiles-operator-exists` | mgmt operator subscription |
| `ocp4-storageclass-encryption-enabled` | mgmt `storageclasses` (AWS-gated) |
| `ocp4-tls-version-check-router` | mgmt `router-default` deployment |

NOTE: `ocp4-oauth-or-oauthclient-inactivity-timeout` is a known inconsistency — the IdP
rules (`idp_is_configured`, `ocp_idp_no_htpasswd`, `ocp_no_ldap_insecure`) were made
HyperShift-aware by reading `HostedCluster.spec.configuration.oauth`, but this rule was
not, even though the same data source would work. It is a good candidate for an upstream
fix rather than a permanent exclusion.

## 5. Should you actually disable them? Two caveats

1. **Some "wrong-target" checks still have real defensive value on the management
   cluster**, because the hosted control plane runs there as ordinary pods. Management
   cluster SCCs, RBAC, and NetworkPolicies are part of the hosted control plane's
   security boundary. If the management cluster is *also* scanned with a plain
   (non-tailored) `ocp4-cis` profile — which is the recommended setup — you lose nothing
   by disabling them in the tailored scan, and you avoid double counting.
2. **Disabling changes your compliance report.** If an auditor expects the full CIS rule
   set, prefer documenting the exclusions (this document, plus the TailoredProfile
   `rationale` fields) over silently shrinking the profile.

Recommended setup, in short:

- Tailored scan (this profile) on the management cluster: hosted control plane coverage.
- Plain `ocp4-cis` / `ocp4-cis-node` scan of the management cluster itself: management
  cluster coverage (this is where the disabled rules get their real answer).
- Compliance Operator inside the hosted cluster (when feasible): in-cluster coverage for
  the hosted cluster (RBAC, SCC, registries, routes, namespaces, and the manual checks).

## 6. Example: TailoredProfile with exclusions (CIS)

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: hypershift-cis-mycluster
  namespace: openshift-compliance
spec:
  extends: ocp4-cis
  title: CIS scan of hosted control plane "mycluster"
  description: >-
    Scans the control plane of HostedCluster "mycluster" from the management
    cluster. Rules that would evaluate management-cluster resources are
    disabled; they are covered by the management cluster's own ocp4-cis scan.
  setValues:
  - name: ocp4-hypershift-cluster
    value: mycluster
    rationale: hosted cluster to scan
  - name: ocp4-hypershift-namespace-prefix
    value: clusters
    rationale: namespace containing the HostedCluster CR
  disableRules:
  - name: ocp4-api-server-anonymous-auth
    rationale: Reads management-cluster RBAC; not about the hosted cluster
  - name: ocp4-api-server-kube-no-unsupported-config-overrides
    rationale: Reads management-cluster kubeapiservers operator CR
  - name: ocp4-api-server-no-unsupported-config-overrides
    rationale: Reads management-cluster openshiftapiservers operator CR
  - name: ocp4-api-server-oauth-https-serving-cert
    rationale: Reads management-cluster apiservers/cluster
  - name: ocp4-api-server-openshift-https-serving-cert
    rationale: Reads management-cluster apiservers/cluster
  - name: ocp4-api-server-profiling-protected-by-rbac
    rationale: Reads management-cluster clusterroles
  - name: ocp4-api-server-tls-security-profile-custom-min-tls-version
    rationale: Reads management-cluster apiservers/cluster
  - name: ocp4-api-server-tls-security-profile-not-old
    rationale: Reads management-cluster apiservers/cluster
  - name: ocp4-audit-logging-enabled
    rationale: Reads management-cluster audit configuration
  - name: ocp4-audit-profile-set
    rationale: Reads management-cluster audit configuration
  - name: ocp4-ingress-controller-tls-cipher-suites
    rationale: Reads management-cluster ingresscontroller
  - name: ocp4-ocp-allowed-registries
    rationale: Reads management-cluster images/cluster
  - name: ocp4-ocp-allowed-registries-for-import
    rationale: Reads management-cluster images/cluster
  - name: ocp4-ocp-insecure-allowed-registries-for-import
    rationale: Reads management-cluster images/cluster
  - name: ocp4-ocp-insecure-registries
    rationale: Reads management-cluster images/cluster
  - name: ocp4-rbac-debug-role-protects-pprof
    rationale: Reads management-cluster clusterroles
  - name: ocp4-scc-limit-container-allowed-capabilities
    rationale: Reads management-cluster SCCs
  - name: ocp4-scheduler-profiling-protected-by-rbac
    rationale: Reads management-cluster clusterroles
  - name: ocp4-scheduler-service-protected-by-rbac
    rationale: Reads management-cluster clusterroles
```

Add the manual rules from section 4.1 to `disableRules` as well if you track manual
attestations on the hosted-cluster side and want to avoid double counting.

## 7. Support FAQ

**Q: A CIS result on my hosted-cluster scan changed after I edited something on the
management cluster. Why?**
That rule is one of the wrong-target rules in section 4 — it reads a management-cluster
resource. Disable it in the TailoredProfile or interpret it as a management-cluster
finding.

**Q: `ocp4-kubeadmin-removed` (or `configure-network-policies`) shows NOT-APPLICABLE on
the tailored scan. Is that a bug?**
No. Those rules carry `platform: not ocp4-on-hypershift` and are intentionally suppressed
on the management scan because they cannot say anything meaningful about the hosted
cluster. Check them via the hosted-cluster scan.

**Q: All HyperShift-aware rules report errors / the scan can't find resources.**
Verify the two variables: `ocp4-hypershift-cluster` must equal the NAME and
`ocp4-hypershift-namespace-prefix` the NAMESPACE from `oc get hostedcluster -A`. The
control plane namespace is `<prefix>-<name>` (default scheme `clusters-<name>`). Also
confirm the operator's service account can read that namespace and
`hostedclusters.hypershift.openshift.io`.

**Q: Why aren't node profiles supported?**
Node rules inspect files on the nodes the scan pods run on. From the management cluster
you can only reach management-cluster nodes; the hosted cluster's worker nodes must be
scanned by a Compliance Operator running inside the hosted cluster.

**Q: Can I name a hosted cluster "None"?**
Do not. The literal string `None` is the sentinel default for `ocp4-hypershift-cluster`;
a cluster with that name would be undetectable by this mechanism.

## 8. Appendix: how this classification was produced

- Rule inventory: `controls/cis_ocp_190/section-*.yml` and `controls/pcidss_4_ocp4.yml`
  in ComplianceAsCode/content, filtered the way the platform profiles do
  (`products/ocp4/profiles/cis-1-9.profile` `filter_rules` drops node-platform rules).
- A rule counts as HyperShift-aware when its `rule.yml` templates the fetch path with
  `{{.hypershift_cluster}}` / `{{.hypershift_namespace_prefix}}`.
- Platform gating read from each rule's `platform:` key
  (`ocp4-on-hypershift` = management scan, `ocp4-on-hypershift-hosted` = hosted scan).
- Automated vs. manual determined by presence of a check `template:`/`warnings:` block;
  manual rules have only OCIL instructions and always report MANUAL.
- Operator mechanics: `cmd/manager/scap.go` (`FigureResources`, `getResourcePaths`),
  `pkg/utils/parse_arf_result.go` (`GetPathFromWarningXML`),
  `pkg/utils/xml2text.go` (`RenderValues`, Go `text/template` with `missingkey=zero`).
- CPE detection: `shared/applicability/ocp4-on-hypershift{,-hosted}.yml` and
  `shared/applicability/oval/installed_app_is_ocp4.xml`
  (`installed_app_is_ocp4_on_hypershift{,_hosted}` definitions).
