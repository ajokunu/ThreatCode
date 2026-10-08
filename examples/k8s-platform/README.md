# k8s-platform

A Kubernetes platform in seven manifests.

An Ingress routes to a Service, which selects a Deployment.
The Deployment reads one Secret directly through `secretKeyRef`, and runs as a ServiceAccount that a ClusterRoleBinding ties to a ClusterRole allowed to read every Secret in the cluster.
A separate DaemonSet runs privileged on the host with host networking, host PID and a `hostPath` mount of the node root.

| File | What it is |
|------|------------|
| `namespace.yaml` | The `platform` namespace, without Pod Security Admission labels. |
| `ingress.yaml`, `service.yaml` | The route in from the internet. |
| `deployment.yaml`, `secret.yaml` | The storefront workload and the payment API key. |
| `rbac.yaml` | The ServiceAccount, the `secret-reader` ClusterRole and the binding. |
| `daemonset.yaml` | The privileged node exporter. |

## Scan the manifests

<!-- runnable exit=1 -->

```bash
threatcode scan examples/k8s-platform
```

The manifests are in separate files, and one graph covers all of them, so paths cross files:

<!-- gen:report -->
```text
ThreatCode scan of .: 9 resources, 30 findings

Verdict: 1 critical, 6 high, 13 medium, 10 low, 2 attack paths from the internet to data

Attack paths (2)
HIGH      internet -> kubernetes_secret.platform.payment-api-key  (4 hops, id 46909caa9306)
          internet > kubernetes_ingress.platform.storefront > kubernetes_service.platform.storefront
          > kubernetes_deployment.platform.storefront > kubernetes_secret.platform.payment-api-key
HIGH      internet -> kubernetes_secret.platform.payment-api-key  (6 hops, id 141ad2ba8eed)
          internet > kubernetes_ingress.platform.storefront > kubernetes_service.platform.storefront
          > kubernetes_deployment.platform.storefront >
          kubernetes_service_account.platform.storefront-sa > kubernetes_cluster_role.secret-reader
          > kubernetes_secret.platform.payment-api-key

Findings (30)
SEVERITY  RESOURCE                 RULE                          FINDING
CRITICAL  kubernet...ode-exporter  K8S_PRIVILEGED_CONTAINER      Container running in privileged...
HIGH      kubernet...ecret-reader  K8S_RBAC_SECRETS_READ         Role can read Secrets
HIGH      kubernet...ode-exporter  K8S_HOST_NETWORK              Pod uses host network namespace
HIGH      kubernet...ode-exporter  K8S_HOST_PATH_VOLUME          hostPath volume mount detected
HIGH      kubernet...ode-exporter  K8S_HOST_PID                  Pod uses host PID namespace
HIGH      kubernet...m.storefront  K8S_NO_SECCOMP_PROFILE        Container without a seccomp profile
HIGH      kubernet...m.storefront  boundary                      Trust boundary crossing: kuberne...
MEDIUM    kubernet...ode-exporter  K8S_ALLOW_PRIVILEGE_ESCAL...  Container allows privilege escal...
MEDIUM    kubernet...ode-exporter  K8S_NO_RESOURCE_LIMITS        Container without CPU and memory...
MEDIUM    kubernet...ode-exporter  K8S_NO_SECCOMP_PROFILE        Container without a seccomp profile
MEDIUM    kubernet...ode-exporter  K8S_RUN_AS_ROOT               Container may run as root
MEDIUM    kubernet...m.storefront  boundary                      Trust boundary crossing: kuberne...
MEDIUM    kubernet...m.storefront  K8S_AUTOMOUNT_SA_TOKEN        Workload mounts a service accoun...
MEDIUM    kubernet...m.storefront  K8S_CAPABILITIES_NOT_DROPPED  Container capabilities not dropped
MEDIUM    kubernet...m.storefront  K8S_DEFAULT_ALLOW_EGRESS      Workload not covered by an egres...
MEDIUM    kubernet...m.storefront  K8S_NO_NETWORK_POLICY         Workload not covered by an ingre...
MEDIUM    kubernet...m.storefront  K8S_NO_SECURITY_CONTEXT_D...  Pod without pod-level runAsNonRoot
MEDIUM    kubernet...m.storefront  K8S_SECRET_ENV_VAR            Secret referenced via environmen...
MEDIUM    kubernet...m.storefront  boundary                      Trust boundary crossing: interne...
MEDIUM    kubernet...ace.platform  K8S_NO_PSA_LABELS             Namespace without Pod Security A...
LOW       kubernet...ode-exporter  K8S_AUTOMOUNT_SA_TOKEN        Workload mounts a service accoun...
LOW       kubernet...ode-exporter  K8S_CAPABILITIES_NOT_DROPPED  Container capabilities not dropped
LOW       kubernet...ode-exporter  K8S_DEFAULT_ALLOW_EGRESS      Workload not covered by an egres...
LOW       kubernet...ode-exporter  K8S_DEFAULT_SERVICE_ACCOUNT   Pod uses the default service acc...
LOW       kubernet...ode-exporter  K8S_EPHEMERAL_STORAGE_UNB...  Container without ephemeral stor...
LOW       kubernet...ode-exporter  K8S_NO_NETWORK_POLICY         Workload not covered by an ingre...
LOW       kubernet...ode-exporter  K8S_NO_SECURITY_CONTEXT_D...  Pod without pod-level runAsNonRoot
LOW       kubernet...ode-exporter  K8S_WRITABLE_ROOT_FS          Container root filesystem is wri...
LOW       kubernet...m.storefront  K8S_EPHEMERAL_STORAGE_UNB...  Container without ephemeral stor...
LOW       kubernet...torefront-sa  K8S_AUTOMOUNT_DEFAULT         ServiceAccount does not disable...

Coverage: 8 files discovered, 7 units parsed, 1 not infrastructure
  No input errors or coverage gaps were recorded.
```
<!-- /gen:report -->

The attack paths:

<!-- gen:paths -->
1. **high**, 4 hops, id `46909caa9306`: `internet` -> `kubernetes_ingress.platform.storefront` -> `kubernetes_service.platform.storefront` -> `kubernetes_deployment.platform.storefront` -> `kubernetes_secret.platform.payment-api-key`
   ATT&CK techniques: T1190, T1552.007.
2. **high**, 6 hops, id `141ad2ba8eed`: `internet` -> `kubernetes_ingress.platform.storefront` -> `kubernetes_service.platform.storefront` -> `kubernetes_deployment.platform.storefront` -> `kubernetes_service_account.platform.storefront-sa` -> `kubernetes_cluster_role.secret-reader` -> `kubernetes_secret.platform.payment-api-key`
   ATT&CK techniques: T1190, T1552.007.
<!-- /gen:paths -->

The first path is the direct one: Ingress, Service, Deployment, and the Secret the Deployment reads.
The second goes through cluster RBAC: the Deployment's ServiceAccount is bound to a ClusterRole that reads Secrets, so a compromise of the workload reaches every Secret it may read, including the payment key.
The privileged DaemonSet is the one critical finding (`K8S_PRIVILEGED_CONTAINER`).
It has no attack path of its own, because no Service or Ingress reaches it, but a compromise of that pod is a compromise of the node.

Kubernetes attack paths come from Ingress and Service flows, the Secrets a workload reads, the ServiceAccount it runs as, and the Roles a binding grants.
Matching is by namespace and label selector, so a Service reaches the workloads whose pod labels contain its selector.

## Gate on critical only

<!-- runnable exit=1 -->

```bash
threatcode scan examples/k8s-platform --fail-on critical --min-severity high -f text -o report.txt
```

Exit code 1 because the privileged DaemonSet is critical.
`--min-severity` only hides findings below high from the report, and `--fail-on` decides the exit code, so the two are independent.
