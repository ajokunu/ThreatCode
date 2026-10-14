# Kubernetes

Source shape: manifests as written for `kubectl apply` and as printed by `kubectl get -o yaml` and `-o json`.
source: handbuilt (the `List` files copy the server-populated fields kubectl prints: `uid`, `resourceVersion`, `creationTimestamp`, `status`, defaulted fields).

| File | Contents |
| --- | --- |
| `shop_stack.yaml` | One multi-document file: Namespace with pod-security labels, ServiceAccount, ConfigMap, Secret, Role, RoleBinding, a hardened Deployment using the ServiceAccount, the ConfigMap and the Secret, a Service selecting it, an Ingress with TLS routing to the Service, a default-deny NetworkPolicy and an allow policy. |
| `workloads.yaml` | Every pod workload kind (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, Pod) with pod-level `securityContext`, an init container, a privileged sidecar, host namespaces, a `hostPath` volume and added capabilities. |
| `kubectl_get_all.yaml`, `kubectl_get_all.json` | The `List` kind with a Deployment, a `LoadBalancer` Service and a ConfigMap as `kubectl get deploy,svc,cm -o yaml` and `-o json` print them. |
