#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."
mkdir -p docs
exec > >(tee docs/rollback-experiment.log) 2>&1

NS="rollback-lab"
DEPLOY="rollback-demo"
GOOD_IMAGE="k8s-security-platform-security-platform:latest"

echo "=== Kubernetes rollback experiment ==="
date -Is

echo
echo "1. Create isolated namespace"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

echo
echo "2. Deploy known-good local image"
cat <<YAML | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${DEPLOY}
  namespace: ${NS}
  labels:
    app: rollback-demo
spec:
  replicas: 1
  revisionHistoryLimit: 5
  selector:
    matchLabels:
      app: rollback-demo
  template:
    metadata:
      labels:
        app: rollback-demo
    spec:
      containers:
        - name: app
          image: ${GOOD_IMAGE}
          imagePullPolicy: Never
          ports:
            - containerPort: 5000
          env:
            - name: SECURITY_DB
              value: /tmp/rollback-lab.db
YAML

kubectl rollout status "deployment/$DEPLOY" -n "$NS" --timeout=120s
kubectl rollout history "deployment/$DEPLOY" -n "$NS"

echo
echo "3. Introduce a deliberately invalid image"
kubectl set image "deployment/$DEPLOY" \
  app=missing-image:rollback-test -n "$NS"

echo
echo "4. Confirm the bad rollout fails"
if kubectl rollout status "deployment/$DEPLOY" -n "$NS" --timeout=25s; then
  echo "ERROR: The bad rollout unexpectedly succeeded."
  exit 1
else
  echo "EXPECTED RESULT: Bad rollout did not become ready."
fi

kubectl get pods -n "$NS" -o wide

echo
echo "5. Roll back to the previous revision"
kubectl rollout undo "deployment/$DEPLOY" -n "$NS"
kubectl rollout status "deployment/$DEPLOY" -n "$NS" --timeout=120s

echo
echo "6. Verify restored image and ready replica"
ACTUAL_IMAGE="$(kubectl get deployment "$DEPLOY" -n "$NS" \
  -o jsonpath='{.spec.template.spec.containers[0].image}')"
READY="$(kubectl get deployment "$DEPLOY" -n "$NS" \
  -o jsonpath='{.status.readyReplicas}')"

echo "Expected image: $GOOD_IMAGE"
echo "Actual image:   $ACTUAL_IMAGE"
echo "Ready replicas: ${READY:-0}"

if [[ "$ACTUAL_IMAGE" != "$GOOD_IMAGE" || "${READY:-0}" != "1" ]]; then
  echo "ERROR: Rollback verification failed."
  exit 1
fi

echo
kubectl rollout history "deployment/$DEPLOY" -n "$NS"
kubectl get deployment,pods -n "$NS"
echo
echo "PASS: Failed rollout detected and previous image restored."
echo "Evidence saved to docs/rollback-experiment.log"
date -Is
