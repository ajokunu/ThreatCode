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
ThreatCode scan of examples/k8s-platform: 9 resources, 30 findings

Verdict: 1 critical, 6 high, 13 medium, 10 low, 2 attack paths from the internet to secret stores,
         worst high

Attack paths (2)
P1  HIGH      internet -> kubernetes_secret.platform.payment-api-key
    secret store, 4 hops, score 7.7; 7 findings enable it, the worst being HIGH
    K8S_NO_SECCOMP_PROFILE.
    internet > kubernetes_ingress.platform.storefront > kubernetes_service.platform.storefront
    > kubernetes_deployment.platform.storefront > kubernetes_secret.platform.payment-api-key
    enabled by:
      kubernetes_deployment.platform.storefront -> kubernetes_secret.platform.payment-api-key: HIGH
        K8S_NO_SECCOMP_PROFILE, MEDIUM K8S_AUTOMOUNT_SA_TOKEN, MEDIUM K8S_CAPABILITIES_NOT_DROPPED,
        +4 more
    ignore id: 46909caa9306

P2  HIGH      internet -> kubernetes_secret.platform.payment-api-key
    secret store, 6 hops, score 7.3; 9 findings enable it, the worst being HIGH
    K8S_NO_SECCOMP_PROFILE.
    internet > kubernetes_ingress.platform.storefront > kubernetes_service.platform.storefront
    > kubernetes_deployment.platform.storefront > kubernetes_service_account.platform.storefront-sa
    > kubernetes_cluster_role.secret-reader > kubernetes_secret.platform.payment-api-key
    enabled by:
      kubernetes_deployment.platform.storefront ->
        kubernetes_service_account.platform.storefront-sa: HIGH K8S_NO_SECCOMP_PROFILE, MEDIUM
        K8S_AUTOMOUNT_SA_TOKEN, MEDIUM K8S_CAPABILITIES_NOT_DROPPED, +4 more
      kubernetes_service_account.platform.storefront-sa -> kubernetes_cluster_role.secret-reader:
        LOW K8S_AUTOMOUNT_DEFAULT
      kubernetes_cluster_role.secret-reader -> kubernetes_secret.platform.payment-api-key: HIGH
        K8S_RBAC_SECRETS_READ
    ignore id: 141ad2ba8eed

Findings (30, 23 rows after grouping)
SEVERITY  RESOURCE                                           RULE                             PATHS
          FINDING  LOCATION  ATT&CK  STRIDE
CRITICAL  kubernetes_daemon_set.platform.node-exporter       K8S_PRIVILEGED_CONTAINER
          Container running in privileged mode  daemonset.yaml:1  T1611  EoP
HIGH      kubernetes_cluster_role.secret-reader              K8S_RBAC_SECRETS_READ            P2
          Role can read Secrets  rbac.yaml:7  T1552.007  Info disclosure
HIGH^     kubernetes_deployment.platform.storefront          K8S_NO_SECCOMP_PROFILE           P1,P2
          Container without a seccomp profile (+2 related: container hardening)  deployment.yaml:1
          T1611  EoP
          also K8S_CAPABILITIES_NOT_DROPPED, K8S_NO_SECURITY_CONTEXT_DEFAULTS
HIGH      kubernetes_daemon_set.platform.node-exporter       K8S_HOST_NETWORK
          Pod uses host network namespace  daemonset.yaml:1  T1040  Info disclosure
HIGH      kubernetes_daemon_set.platform.node-exporter       K8S_HOST_PATH_VOLUME
          hostPath volume mount detected  daemonset.yaml:1  T1611  EoP
HIGH      kubernetes_daemon_set.platform.node-exporter       K8S_HOST_PID
          Pod uses host PID namespace  daemonset.yaml:1  T1611  EoP
HIGH      kubernetes_ingress.platform.storefront             BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to kubernetes_service.platform.storefront (tcp/80)
          ingress.yaml:1  T1565.002  Tampering
MEDIUM^   kubernetes_deployment.platform.storefront          K8S_AUTOMOUNT_SA_TOKEN           P1,P2
          Workload mounts a service account token it may not need  deployment.yaml:1  T1528  EoP
MEDIUM^   kubernetes_deployment.platform.storefront          K8S_DEFAULT_ALLOW_EGRESS         P1,P2
          Workload not covered by an egress NetworkPolicy  deployment.yaml:1  T1048  Info disclosure
MEDIUM^   kubernetes_deployment.platform.storefront          K8S_NO_NETWORK_POLICY            P1,P2
          Workload not covered by an ingress NetworkPolicy  deployment.yaml:1  T1046  Info
          disclosure
MEDIUM^   kubernetes_deployment.platform.storefront          K8S_SECRET_ENV_VAR               P1,P2
          Secret referenced via environment variable  deployment.yaml:1  T1552.001  Info disclosure
MEDIUM    kubernetes_daemon_set.platform.node-exporter       K8S_ALLOW_PRIVILEGE_ESCALATION
          Container allows privilege escalation (+5 related: container hardening)  daemonset.yaml:1
          T1548,T1611,T1105  EoP
          also K8S_NO_SECCOMP_PROFILE, K8S_RUN_AS_ROOT, K8S_CAPABILITIES_NOT_DROPPED,
               K8S_NO_SECURITY_CONTEXT_DEFAULTS, K8S_WRITABLE_ROOT_FS
MEDIUM    kubernetes_daemon_set.platform.node-exporter       K8S_NO_RESOURCE_LIMITS
          Container without CPU and memory limits  daemonset.yaml:1  T1499  DoS
MEDIUM    kubernetes_deployment.platform.storefront          BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to kubernetes_secret.platform.payment-api-key
          deployment.yaml:1  T1530,T1565.002  Tampering
MEDIUM    kubernetes_ingress.platform.storefront             BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, internet > dmz: from the internet (https/443)  ingress.yaml:1
          T1190,T1565.002  Tampering
MEDIUM    kubernetes_namespace.platform                      K8S_NO_PSA_LABELS
          Namespace without Pod Security Admission enforce label  namespace.yaml:1  T1611  EoP
LOW       kubernetes_service_account.platform.storefront-sa  K8S_AUTOMOUNT_DEFAULT            P2
          ServiceAccount does not disable token automounting  rbac.yaml:1  T1528  EoP
LOW       kubernetes_daemon_set.platform.node-exporter       K8S_AUTOMOUNT_SA_TOKEN
          Workload mounts a service account token it may not need  daemonset.yaml:1  T1528  EoP
LOW       kubernetes_daemon_set.platform.node-exporter       K8S_DEFAULT_ALLOW_EGRESS
          Workload not covered by an egress NetworkPolicy  daemonset.yaml:1  T1048  Info disclosure
LOW       kubernetes_daemon_set.platform.node-exporter       K8S_DEFAULT_SERVICE_ACCOUNT
          Pod uses the default service account  daemonset.yaml:1  T1078.001  EoP
LOW       kubernetes_daemon_set.platform.node-exporter       K8S_EPHEMERAL_STORAGE_UNBOUNDED
          Container without ephemeral storage limit  daemonset.yaml:1  T1499  DoS
LOW       kubernetes_daemon_set.platform.node-exporter       K8S_NO_NETWORK_POLICY
          Workload not covered by an ingress NetworkPolicy  daemonset.yaml:1  T1046  Info disclosure
LOW       kubernetes_deployment.platform.storefront          K8S_EPHEMERAL_STORAGE_UNBOUNDED
          Container without ephemeral storage limit  deployment.yaml:1  T1499  DoS
Key: ^ severity raised from the rule's own by context; P1, P2: the attack paths above that the
     finding enables

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
