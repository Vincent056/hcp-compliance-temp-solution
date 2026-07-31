# Validation Report: Compliance Operator v1.9.1 Scanning a Hosted Control Plane from the Management Cluster

**Date:** 2026-07-31 (UTC)
**Environment:** OpenShift `4.21.0-0.nightly-2026-07-20-173555` CI launch cluster on AWS
(us-east-1, 3 masters + 3 workers spanning 2 AZs), cluster
`ci-ln-b6zqd5k-76ef8.aws-4.ci.openshift.org`.
**Components under test:** Compliance Operator **v1.9.1** (downstream, `redhat-operators`,
`stable` channel), MCE **v2.17.1** (downstream Hosted Control Planes), HostedCluster
`hcp-demo` (none-platform, control-plane-only, same 4.21 nightly release image).

**Verdict: PASS.** The documented management-cluster tailored-scan flow works end to end
on the latest downstream operator: HyperShift platform detection fired, dual-path rules
fetched the hosted control plane's configuration, platform-gated rules
suppressed/activated correctly, and the scan produced genuine hosted-cluster findings.
One content bug was found (etcd rules false-positive on 4.21 HCP, details in section 5).

---

## 1. What was installed and how

| Step | Detail |
|---|---|
| Compliance Operator | Namespace `openshift-compliance` + OperatorGroup + Subscription (`stable`/`redhat-operators`) -> CSV `compliance-operator.v1.9.1` Succeeded; ProfileBundles `ocp4`/`rhcos4` VALID; `ocp4-cis` profile v1.9.0; variables `ocp4-hypershift-cluster` and `ocp4-hypershift-namespace-prefix` present |
| Hosted Control Planes | Subscription `multicluster-engine` (`stable-2.17`) -> CSV v2.17.1 Succeeded -> `MultiClusterEngine` CR -> hypershift operator Running in `hypershift` namespace (via `hypershift-addon` on `local-cluster`) |
| HostedCluster | `hcp-demo` in namespace `clusters`, `platform.type: None` (control-plane-only, no workers), managed etcd on PV, APIServer via LoadBalancer, release image = management cluster's own nightly (CI pull secret covers `registry.ci.openshift.org`) |

Control plane reached `Available=True` with 30/32 pods running in the
`clusters-hcp-demo` namespace, `kas-config`/`openshift-apiserver` ConfigMaps and
`app=etcd` / `app=kube-controller-manager` pods present — every artifact the
HyperShift-aware rules fetch.

## 2. Environment issues hit and their fixes (useful for support)

1. **HyperShift admission webhook race** — `no endpoints available for service
   "operator"` when creating the HostedCluster seconds after the operator deployed.
   Retry until the webhook endpoints exist.
2. **KAS never deployed; etcd stuck 2/3** — with the default
   `controllerAvailabilityPolicy: HighlyAvailable`, etcd spreads across zones; this CI
   cluster spans only 2 AZs, so `etcd-1` stayed Pending
   (`didn't match pod anti-affinity rules`) and the CPO gated the kube-apiserver
   component on the full etcd statefulset even though `EtcdAvailable=True
   (QuorumAvailable)`. Fix: recreate with
   `spec.controllerAvailabilityPolicy: SingleReplica` (field is immutable). On real
   production management clusters with 3+ AZs this does not occur.
3. **`redhat-operators-catalog` ImagePullBackOff blocked Available** — no released
   v4.21 catalog index exists for nightlies, and the CPO waits for the catalog
   components. Fix: recreate with `spec.olmCatalogPlacement: guest` (also immutable).
   GA-release hosted clusters do not hit this.

Total time from HostedCluster apply to `Available=True` with the fixed spec: ~6 minutes.

## 3. The scan under test

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: hypershift-cis-hcp-demo
  namespace: openshift-compliance
spec:
  extends: ocp4-cis
  title: CIS scan of hosted control plane hcp-demo
  setValues:
  - name: ocp4-hypershift-cluster
    value: hcp-demo          # NAME from `oc get hostedcluster -A`
    rationale: HyperShift version detection
  - name: ocp4-hypershift-namespace-prefix
    value: clusters          # NAMESPACE from `oc get hostedcluster -A`
    rationale: control plane namespace detection
```

Bound to the `default` ScanSetting via a ScanSettingBinding. TailoredProfile went
`READY`, scan `hypershift-cis-hcp-demo` ran to `DONE / NON-COMPLIANT` in ~3 minutes.

## 4. Validation evidence (each mechanism checked individually)

**4.1 Dual-path fetches hit the hosted control plane.** The api-resource-collector log
of the scan pod shows the templated path resolved from the variables
(`clusters` + `hcp-demo` -> `clusters-hcp-demo`):

```
Fetching URI: '/api/v1/namespaces/clusters-hcp-demo/configmaps/kas-config'   (x9 rules)
```

**4.2 Platform (CPE) detection fired.** Three independent confirmations:

- `ocp4-kubeadmin-removed`, `ocp4-configure-network-policies`,
  `ocp4-configure-network-policies-namespaces` produced **no
  ComplianceCheckResult** (platform `not ocp4-on-hypershift` -> NOT-APPLICABLE,
  hidden by default).
- `audit-log-forwarding-webhook` (platform `ocp4-on-hypershift` — only runs on a
  management cluster) **did** produce a result: FAIL, correct because the
  HostedCluster sets no `spec.auditWebhook`.
- `configure-network-policies-hypershift-hosted` (same mgmt-only platform) produced
  PASS — HyperShift's default NetworkPolicies in the CP namespace satisfy it.

**4.3 Result totals.** 87 ComplianceCheckResults: **49 PASS / 21 MANUAL / 17 FAIL**
(scan result NON-COMPLIANT, as expected for an unhardened cluster).

**4.4 Genuine hosted-cluster findings (the scan is really assessing hcp-demo):**

| Result | Status | Why it is correct |
|---|---|---|
| `api-server-encryption-provider-cipher` | FAIL | HostedCluster has no `spec.secretEncryption` -> hosted etcd secrets not encrypted. Read from the HostedCluster CR, not the mgmt `apiservers/cluster`. |
| `idp-is-configured` | FAIL | No `spec.configuration.oauth` on the HostedCluster |
| `audit-log-forwarding-webhook` | FAIL | No `spec.auditWebhook` |
| `api-server-audit-log-maxbackup` / `-maxsize` + `ocp-api-server-*` variants (4) | FAIL | Hosted `kas-config` really sets `audit-log-maxbackup: 1`, `audit-log-maxsize: 10` — below CIS thresholds. Verified by reading the ConfigMap directly. True finding about HCP defaults. |
| `api-server-client-ca`, `api-server-audit-log-path`, `api-server-admission-control-plugin-scc`, `controller-use-service-account`, `kubelet-disable-readonly-port`, ... | PASS | Read from `kas-config` / CP pods in `clusters-hcp-demo` |

**4.5 Wrong-target rules behaved exactly as documented** (results reflect the CI
management cluster, not hcp-demo): `audit-profile-set` FAIL (mgmt audit profile is
`Default`), `ingress-controller-tls-cipher-suites` FAIL (mgmt default
IngressController), `ocp-allowed-registries` / `ocp-allowed-registries-for-import`
FAIL (mgmt `images/cluster` unset). These four are on the disable list in
`HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md`; this run demonstrates live why.

## 5. Bug found: etcd rules false-positive on 4.21 hosted control planes

All six etcd results FAILed: `etcd-cert-file`, `etcd-key-file`,
`etcd-client-cert-auth`, `etcd-peer-cert-file`, `etcd-peer-key-file`,
`etcd-peer-client-cert-auth`. These are **false positives**:

- The content's HyperShift path for these rules greps the etcd **pod command-line
  arguments** (`/api/v1/namespaces/<cp-ns>/pods?labelSelector=app%3Detcd`).
- The 4.21 hosted etcd is started as
  `/bin/sh -c 'ETCD_INITIAL_CLUSTER_STATE=$(...) /usr/bin/etcd'` — **no flags** — and
  receives its entire TLS configuration via environment variables, which are set and
  secure:

  ```
  ETCD_CERT_FILE=/etc/etcd/tls/server/server.crt
  ETCD_CLIENT_CERT_AUTH=true
  ETCD_PEER_CERT_FILE=/etc/etcd/tls/peer/peer.crt
  ETCD_PEER_KEY_FILE=/etc/etcd/tls/peer/peer.key
  ETCD_PEER_TRUSTED_CA_FILE=/etc/etcd/tls/etcd-ca/ca.crt
  ETCD_PEER_CLIENT_CERT_AUTH=true
  ```

- Fix needed in ComplianceAsCode: the six `etcd_*` rules' hypershift jqfilters must
  also match `.spec.containers[].env[]` (`ETCD_CERT_FILE` etc.), not only args.
  Until fixed, treat these six as known false positives on HCP >= 4.21 (attach the
  env-var evidence above as the compensating check).

## 6. Reproduction quick reference

```bash
# 1. Operators
oc apply -f co-subscription.yaml           # stable / redhat-operators -> v1.9.1
oc apply -f mce-subscription.yaml          # stable-2.17 -> v2.17.1
oc apply -f - <<<'{"apiVersion":"multicluster.openshift.io/v1","kind":"MultiClusterEngine","metadata":{"name":"multiclusterengine"},"spec":{}}'

# 2. Hosted cluster (CI-sized: single replica, guest catalogs)
oc apply -f hostedcluster.yaml             # platform None, SingleReplica, olmCatalogPlacement guest
oc wait hostedcluster/hcp-demo -n clusters --for=condition=Available --timeout=15m

# 3. Scan
oc apply -f tailoredprofile.yaml ssb.yaml
oc wait compliancescan/hypershift-cis-hcp-demo -n openshift-compliance \
  --for=jsonpath='{.status.phase}'=DONE --timeout=10m

# 4. Key validation checks
oc logs <scan-pod> -c api-resource-collector | grep clusters-hcp-demo   # dual-path proof
oc get ccr | grep kubeadmin                                             # empty = CPE proof
oc get ccr hypershift-cis-hcp-demo-audit-log-forwarding-webhook          # exists = CPE proof
```

Full manifests used in this run are preserved in the session scratchpad
(`hostedcluster.yaml`, `tailoredprofile.yaml`, `ssb.yaml`).

## 7. Follow-ups

1. File the ComplianceAsCode bug for the six etcd rules (env-var matching on HCP
   4.21+), including the evidence in section 5.
2. Consider a docs/KCS note for the two CI-environment HostedCluster immutable fields
   (`controllerAvailabilityPolicy`, `olmCatalogPlacement`) — both required recreation.
3. The wrong-target behavior demonstrated in 4.5 is the motivation for the
   `disableRules` list in `HYPERSHIFT_HOSTED_CP_SCAN_GUIDE.md`; the four rules above
   should be disabled in production tailored profiles.
```

## 8. Follow-up status (added 2026-07-31, post-validation)

- Section 7 item 1 (etcd content bug): filed as CMP-4520.
- Additional findings from the extended validation (STIG/High/CEL scans, in-hosted
  install on AWS HostedCluster hcp-aws): CMP-4521 (hosted CPE unreachable),
  CMP-4522 (CSV master nodeSelector), CMP-4523 (collector nodepools RBAC),
  CMP-4524 (extend HyperShift rule awareness).
- The single-scan validation here grew into the full multi-layer package: see the
  repo README (TL;DR + sections 8-10) and RULE_COVERAGE_MATRIX.md for per-rule
  coverage from both scan locations.
