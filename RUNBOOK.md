# Runbook: launching the scans, reading results, remediating

**Docs:** [README](README.md) · [Runbook](RUNBOOK.md) · [Coverage](COVERAGE.md) · [Design](DESIGN.md) · [Validation](VALIDATION.md) · [Rule Matrix](RULE_COVERAGE_MATRIX.md) · [Background: Scan Mechanics](docs-background/HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md) · [Background: Strategy](docs-background/HCP_STIG_CIS_HIGH_COMPLIANCE_ANALYSIS.md) · [Background: First Validation](docs-background/HCP_SCAN_VALIDATION_REPORT.md)

## Launching the scans

One hosted cluster is assessed by TWO scan locations. Everything below assumes the
Compliance Operator (v1.9.1+) is installed on the management cluster and, for the
in-hosted layer, inside each hosted cluster. All validation in this repo ran on the
DOWNSTREAM product build - `redhat-operators` catalog, `stable` channel, currently
`compliance-operator.v1.9.1` (image
`registry.redhat.io/compliance/openshift-compliance-rhel8-operator`) - on both scan
locations; `hosted/co-install.yaml` subscribes the same source/channel.

**A. Management cluster — hosted control-plane configuration (CIS + STIG + High):**

```
# once per management cluster (applies rules+variables and sets ownerReferences)
./management/deploy.sh

# per hosted cluster: one TailoredProfile per cluster, each with its own setValues
#   CEL TP (management/tp-cel.yaml):    hypershiftcluster / hypershiftprefix
#   OpenSCAP TPs (tp-{cis,stig,high}):  ocp4-hypershift-cluster / -namespace-prefix
# copy each file per cluster, change metadata.name + the two values, then
oc apply -f management/tp-cel.yaml -f management/tp-cis.yaml -f management/tp-stig.yaml -f management/tp-high.yaml
oc get tailoredprofiles -n openshift-compliance     # wait for READY

oc apply -f management/ssb.yaml                     # one SSB per TailoredProfile
oc get compliancescans -n openshift-compliance      # wait for DONE
```

CEL TailoredProfile instances for different hosted clusters run CONCURRENTLY with
the single shared rule set - each scan evaluates its own TP's `setValues`
(validated live with two HostedClusters - [`DESIGN.md`](DESIGN.md)).

Optional fleet-wide gate (one scan over ALL hosted clusters, no per-cluster
attribution): `oc apply -f management/customrules-fleet.yaml -f
management/tp-cel-fleet.yaml` - the file includes the `hcp-cel-fleet`
ScanSettingBinding, so this one apply also starts the scan. Run it as the
scheduled drift catcher; use the per-cluster instances to attribute.

**B. Inside each hosted cluster — in-cluster half + node profiles:**

```
oc apply -f hosted/co-install.yaml        # Subscription overrides are REQUIRED
oc apply -f hosted/customrules.yaml -f hosted/tp.yaml -f hosted/tp-cel.yaml
oc apply -f hosted/ssb.yaml
```

**C. Which scan answers which benchmark:**

| Benchmark | Management side | Inside the hosted cluster |
|---|---|---|
| CIS | `hypershift-cis-<cluster>` + `hcp-cel-<cluster>` | `hosted-cis-tailored` + `ocp4-cis-node` |
| STIG | `hypershift-stig-<cluster>` + `hcp-cel-<cluster>` | `hosted-stig-tailored` + `hosted-cel-oauthclient` + `ocp4-stig-node` |
| High | `hypershift-high-<cluster>` + `hcp-cel-<cluster>` | `hosted-high-tailored` + `hosted-cel-oauthclient` + `ocp4-high-node` |
| (all, optional) | `hcp-cel-fleet` — one gate over every hosted cluster | - |

**Managing the solution's objects:** everything this repo creates carries the
`app.kubernetes.io/part-of: hcp-temp-compliance` label. Inventory and uninstall:

```
oc get rules,customrules,variables,tailoredprofiles,scansettingbindings \
   -n openshift-compliance -l app.kubernetes.io/part-of=hcp-temp-compliance
# uninstall (management side; add clusterrole,clusterrolebinding for the RBAC pair):
oc delete rules,customrules,variables,tailoredprofiles,scansettingbindings \
   -n openshift-compliance -l app.kubernetes.io/part-of=hcp-temp-compliance
```

**D. Reading the results:**

1. Check `hcp-selector-valid` FIRST in each CEL scan: it FAILs when the selected
   HostedCluster does not exist (typo'd selector) - the other `hcp-*` FAILs in
   that scan are then not trustworthy findings. A scan-time ERROR on the rules
   instead means one of the two `setValues` entries is missing in that
   TailoredProfile.
2. Resolve the two split OAuth OR rules across the scan locations: the
   requirement is met if EITHER side passes —
   `hcp-oauth-token-maxage` (mgmt, server half) OR
   `hcp-oauthclient-token-maxage` (in-hosted, client half); same for the
   `-inactivity-timeout` pair.
3. Every remaining FAIL is a genuine finding; see Remediations below for the
   standing ones on an unhardened cluster.

## Remediations for the standing FAILs

| FAIL | Remediation |
|---|---|
| `hcp-fips-enabled` | Recreate the HostedCluster with `spec.fips: true` (immutable) |
| `hcp-etcd-secret-encryption` | Set `HostedCluster.spec.secretEncryption` (kms or aescbc) |
| `hcp-audit-profile` | Set `HostedCluster.spec.configuration.apiServer.audit.profile` to `WriteRequestBodies`/`AllRequestBodies` |
| `hcp-audit-webhook` | Set `HostedCluster.spec.auditWebhook` (audit log offload) |
| `hcp-oauth-token-maxage` / `-inactivity-timeout` | Set `HostedCluster.spec.configuration.oauth.tokenConfig` (server half) — or override on every OAuthClient in the hosted cluster (client half; both proven live) |
| `api-server-audit-log-maxbackup` / `-maxsize` (+ `ocp-` pair) | Hosted KAS ships `--audit-log-maxbackup=1 --audit-log-maxsize=10`, below benchmark thresholds. Fix with the HyperShift **Audit Log Persistence** feature: an `AuditLogPersistenceConfig` CR sets `spec.auditLog.maxSize`/`maxBackup` on the hosted KAS (PVC-backed audit volume). Docs: [Audit Log Persistence (HyperShift)](https://hypershift.pages.dev/how-to/audit-log-persistence/); implementation: [openshift/hypershift#7241](https://github.com/openshift/hypershift/pull/7241). No docs.redhat.com page exists yet. NOTE: this fixes the kube-apiserver pair; the `ocp-api-server-*` (openshift-apiserver) pair has no HCP knob today — RFE needed. On standalone clusters the only mechanism is `unsupportedConfigOverrides` ([KAS KB](https://access.redhat.com/solutions/5993251), [OAS KB](https://access.redhat.com/solutions/5993271)) which is explicitly unsupported. |
| `audit-error-alert-exists` (in-hosted) / `hcp-audit-error-alert-exists` | 4.21 hosted clusters ship no audit-error alert (the hub's [audit-errors PrometheusRule](https://github.com/openshift/cluster-kube-apiserver-operator/blob/main/bindata/assets/alerts/audit-errors.yaml) exists only on standalone/hub clusters, and its `apiserver=~".+-apiserver"` label matcher does not match 4.21 hosted apiserver metrics — OCP 4.22 adds the label). Apply `hosted/remediation-audit-errors.yaml` inside the hosted cluster (same alert, label matcher dropped; validated live: rule flips FAIL→PASS). |
| `idp-is-configured` / `audit-log-forwarding-webhook` | Configure an IdP / audit webhook per your environment (genuine hardening items) |
| `api-server-encryption-provider-cipher` | Same root cause as `hcp-etcd-secret-encryption` — set `spec.secretEncryption` |

---

