#!/bin/bash
# Deploy the management-side CEL rules (native per-TP setValues delivery).
# Applies customrules.yaml (2 selector Variables + 15 Rule CRs) and sets the
# ownerReferences to the ocp4 ProfileBundle that the TailoredProfile controller
# requires on Rules and Variables. Idempotent; re-run after any ProfileBundle
# recreation (ownerReferences bind these objects to the ProfileBundle lifecycle).
set -euo pipefail
NS=openshift-compliance
DIR=$(dirname "$0")

PB_UID=$(oc get profilebundle ocp4 -n "$NS" -o jsonpath='{.metadata.uid}')
if [ -z "$PB_UID" ]; then
  echo "ERROR: ProfileBundle ocp4 not found in $NS (is the Compliance Operator installed?)" >&2
  exit 1
fi
OWNER="[{\"apiVersion\":\"compliance.openshift.io/v1alpha1\",\"kind\":\"ProfileBundle\",\"name\":\"ocp4\",\"uid\":\"$PB_UID\"}]"

oc apply -f "$DIR/customrules.yaml"
oc apply -f "$DIR/rbac-hypershift-read.yaml"

for r in $(oc get rules -n "$NS" -o name | grep '/hcp-'); do
  oc patch "$r" -n "$NS" --type merge -p "{\"metadata\":{\"ownerReferences\":$OWNER}}" >/dev/null
done
for v in hypershiftcluster hypershiftprefix; do
  oc patch variable "$v" -n "$NS" --type merge -p "{\"metadata\":{\"ownerReferences\":$OWNER}}" >/dev/null
done
echo "Deployed: $(oc get rules -n "$NS" -o name | grep -c '/hcp-') hcp-* Rules + 2 selector Variables (ownerReferences -> ProfileBundle ocp4)"
echo "Next: create one TailoredProfile per hosted cluster from management/tp-cel.yaml and bind it (management/ssb.yaml)."

# Post-deploy verification (also run this after operator upgrades or any
# ProfileBundle recreation - see README 7.2 caveats):
COUNT=$(oc get rules -n "$NS" -o name | grep -c '/hcp-')
[ "$COUNT" -eq 15 ] || { echo "WARNING: expected 15 hcp-* Rules, found $COUNT" >&2; exit 1; }
echo "Verified: 15 hcp-* Rules present; objects carry no profile-bundle label (upgrade-sweep immune)."
