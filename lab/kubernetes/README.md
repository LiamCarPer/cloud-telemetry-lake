# Kubernetes audit lab

This is a local **kind** cluster with API-server audit logging, used to prove
the Kubernetes detection plane against real audit events. It is optional: the
committed fixtures (`make k8s-demo`) exercise the same S3/SQS/Lambda path
without a cluster.

## Prerequisites

- Docker
- `kind` and `kubectl` (the lab was verified with kind v0.33.0 and kubectl
  v1.37.1)
- LocalStack running on `localhost:4566`
- The Terraform stack applied (`ot-k8s-raw-*` bucket and queues exist)

## Create the cluster

```bash
mkdir -p /tmp/opencode/k8s-audit
chmod 777 /tmp/opencode/k8s-audit
cp lab/kubernetes/audit-policy.yaml /tmp/opencode/audit-policy.yaml

kind create cluster --config lab/kubernetes/kind-config.yaml
```

The config mounts the audit policy into the node, mounts the audit log
directory at `/tmp/opencode/k8s-audit`, and configures the API server with
`audit-log-path` and `audit-policy-file`.

The audit policy deliberately uses:

- `Request` for workloads and RBAC so privileged pods, hostPath mounts and
  role bindings can be inspected.
- `Metadata` for `pods/exec`, `pods/attach`, secrets and service-account
  tokens so secret contents never enter the audit log.
- `omitStages: [RequestReceived]` to reduce duplicate stages.

## Generate events

```bash
kubectl --context kind-ot-k8s-lab apply -f lab/kubernetes/demo.yaml
kubectl --context kind-ot-k8s-lab wait --for=condition=Ready pod/web -n demo --timeout=120s
kubectl --context kind-ot-k8s-lab exec -n demo web -- sh -c 'id'
kubectl --context kind-ot-k8s-lab get secret -n demo db-creds -o json >/dev/null
kubectl --context kind-ot-k8s-lab create clusterrolebinding demo-escalate-2 \
  --clusterrole=cluster-admin --serviceaccount=demo:viewer
```

`demo.yaml` also creates a privileged/hostPID pod and a pod with a
`/var/run/docker.sock` hostPath mount.

## Ship the audit log

```bash
docker run -d --name ot-k8s-fluent --network host \
  -e AWS_ACCESS_KEY_ID=mock -e AWS_SECRET_ACCESS_KEY=mock \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v /tmp/opencode/k8s-audit:/audit:ro \
  -v "$PWD/lab/kubernetes/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro" \
  -v "$PWD/lab/kubernetes/parsers.conf:/fluent-bit/etc/parsers.conf:ro" \
  fluent/fluent-bit:latest
```

Fluent Bit tails the audit log and uploads gzipped JSON to
`s3://ot-k8s-raw-000000000000/audit/`. The S3 notification drives the
`ot-kubernetes-detector` Lambda.

## Verify

```bash
AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock AWS_DEFAULT_REGION=us-east-1 \
aws --endpoint-url=http://localhost:4566 dynamodb scan --table-name ot_detections \
  --filter-expression 'detection_domain = :d' \
  --expression-attribute-values '{":d":{"S":"kubernetes"}}'

AWS_ACCESS_KEY_ID=mock AWS_SECRET_ACCESS_KEY=mock AWS_DEFAULT_REGION=us-east-1 \
aws --endpoint-url=http://localhost:4566 s3 ls \
  s3://ot-telemetry-staged-000000000000/parsed/ --recursive | grep -E 'k8s_audit|falco'
```

Expected live detections: `K8S_POD_EXEC`, `K8S_SECRET_ACCESS`,
`K8S_PRIVILEGED_POD`, `K8S_SENSITIVE_HOSTPATH`,
`K8S_CLUSTER_ADMIN_BINDING` and `K8S_SERVICE_ACCOUNT_TOKEN`.

## Lessons from the live run

- Kubernetes logs `kubectl exec` with verb `get` (not `create`), and emits
  `ResponseStarted` + `ResponseComplete` stages with the same `auditID`.
  The rule accepts both verbs, and the handler uses
  `requestReceivedTimestamp` + `auditID` to collapse stages into one row.
- `kube-probe` makes anonymous `/readyz` requests. The anonymous-access rule
  ignores health and discovery endpoints; without that, the lab produced
  hundreds of false positives.
- The audit policy must mount the policy file into the API-server static pod
  (`extraVolumes`), not only into the kind node (`extraMounts`).

## Clean up

```bash
docker rm -f ot-k8s-fluent
kind delete cluster --name ot-k8s-lab
```
