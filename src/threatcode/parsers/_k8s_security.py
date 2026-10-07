"""Pod specs, effective security contexts and container facts of Kubernetes workloads.

Every kind that carries a pod (Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job and
CronJob) is read into one property shape, whatever path the kind nests its pod spec under, so
a rule written once applies to all of them.

Security settings use Kubernetes precedence: a container value wins, else the pod value.
Per-container results then fold into the workload with one rule: a flag describes the
workload as unsafe when any applicable container is unsafe, and a protective flag is true only
when every applicable container has it. The outcome does not depend on the order of the
containers.

Which containers are judged for what:

* security settings, images and ports: regular, init and ephemeral containers,
* probes and resource limits: regular containers and sidecars (init containers with
  ``restartPolicy: Always``), because a plain init container runs once and exits.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from threatcode.parsers.image_ref import is_floating_tag, parse_image_ref
from threatcode.vocab import DANGEROUS_CAPABILITIES, normalize_capability

# Kinds whose objects run pods. Maps the kind to its resource type.
WORKLOAD_KINDS: dict[str, str] = {
    "Pod": "kubernetes_pod",
    "Deployment": "kubernetes_deployment",
    "DaemonSet": "kubernetes_daemon_set",
    "StatefulSet": "kubernetes_stateful_set",
    "ReplicaSet": "kubernetes_replica_set",
    "Job": "kubernetes_job",
    "CronJob": "kubernetes_cron_job",
}

# The Helm fallback renderer replaces a value it cannot resolve with a token that starts like
# this. A container image that holds one is unknown, not an untagged image.
PLACEHOLDER_PREFIX = "placeholder-"

ContainerRole = Literal["regular", "init", "sidecar", "ephemeral"]


def as_dict(value: object) -> dict[str, Any]:
    """The value when it is a mapping, else an empty one (a placeholder scalar, null)."""
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list[Any]:
    """The value when it is a list, else an empty one."""
    return value if isinstance(value, list) else []


def as_bool(value: object) -> bool | None:
    """A boolean for ``True``, ``False`` and their string spellings; None for anything else."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def as_str_list(value: object) -> list[str]:
    """Strings of a list; a lone string counts as a one-element list; anything else is empty."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def label_text(value: object) -> str:
    """A label value as text, so ``version: 1`` and ``version: "1"`` compare equal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def string_map(value: object) -> dict[str, str]:
    """A label or selector mapping with every key and value as text."""
    if not isinstance(value, dict):
        return {}
    return {str(key): label_text(item) for key, item in value.items() if item is not None}


# ---------------------------------------------------------------------------------------
# Pod templates
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PodTemplate:
    """The pod a workload runs: its spec and the labels its pods carry."""

    spec: dict[str, Any]
    labels: dict[str, str]


def pod_template(doc: dict[str, Any]) -> PodTemplate | None:
    """The pod template of a workload document; None for a kind that runs no pod.

    A Pod is its own template, a CronJob nests it under ``jobTemplate.spec.template`` and
    every other kind under ``spec.template``. A missing level counts as empty, so a manifest
    with ``jobTemplate: null`` still yields a template with no containers.
    """
    kind = doc.get("kind")
    if kind not in WORKLOAD_KINDS:
        return None
    spec = as_dict(doc.get("spec"))
    if kind == "Pod":
        return PodTemplate(spec, string_map(as_dict(doc.get("metadata")).get("labels")))
    if kind == "CronJob":
        template = as_dict(as_dict(as_dict(spec.get("jobTemplate")).get("spec")).get("template"))
    else:
        template = as_dict(spec.get("template"))
    return PodTemplate(
        as_dict(template.get("spec")),
        string_map(as_dict(template.get("metadata")).get("labels")),
    )


# ---------------------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ContainerView:
    name: str
    role: ContainerRole
    spec: dict[str, Any]

    @property
    def runs_continuously(self) -> bool:
        """Regular containers and sidecars; probes and limits are judged on these."""
        return self.role in ("regular", "sidecar")


def container_views(pod_spec: dict[str, Any]) -> list[ContainerView]:
    """Every container of a pod spec with its role.

    An init container with ``restartPolicy: Always`` is a sidecar: it keeps running next to the
    regular containers.
    """
    views: list[ContainerView] = []
    groups: tuple[tuple[str, ContainerRole], ...] = (
        ("containers", "regular"),
        ("initContainers", "init"),
        ("ephemeralContainers", "ephemeral"),
    )
    for field_name, role in groups:
        for index, container in enumerate(as_list(pod_spec.get(field_name))):
            if not isinstance(container, dict):
                continue
            name = container.get("name")
            label = name if isinstance(name, str) and name else f"{field_name}[{index}]"
            sidecar = role == "init" and container.get("restartPolicy") == "Always"
            views.append(ContainerView(label, "sidecar" if sidecar else role, container))
    return views


# ---------------------------------------------------------------------------------------
# Effective security context
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class EffectiveContext:
    """What the security settings of one container amount to once the pod's are applied."""

    privileged: bool
    run_as_root: bool
    allow_privilege_escalation: bool
    writable_root_fs: bool
    drops_all_capabilities: bool
    dangerous_capabilities: tuple[str, ...]
    seccomp_type: str | None
    has_security_context: bool
    run_as_user: int | None
    run_as_non_root: bool | None


def _first_set(*values: object) -> object:
    for value in values:
        if value is not None:
            return value
    return None


def _user_id(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _seccomp_type(security_context: dict[str, Any]) -> str | None:
    profile_type = as_dict(security_context.get("seccompProfile")).get("type")
    return profile_type if isinstance(profile_type, str) and profile_type else None


def effective_context(container: dict[str, Any], pod_context: dict[str, Any]) -> EffectiveContext:
    """The effective security context of a container under its pod's security context.

    ``runAsNonRoot``, ``runAsUser`` and the seccomp profile take the container value and fall
    back to the pod value. The container is reported as running as root unless
    ``runAsNonRoot`` is true or, when it is unset, ``runAsUser`` is a non-zero number; an
    explicit ``runAsNonRoot: false`` stays root even where the pod says true.
    """
    own = as_dict(container.get("securityContext"))
    non_root = as_bool(_first_set(own.get("runAsNonRoot"), pod_context.get("runAsNonRoot")))
    user = _user_id(_first_set(own.get("runAsUser"), pod_context.get("runAsUser")))
    if non_root is True:
        run_as_root = False
    elif non_root is False:
        run_as_root = True
    else:
        run_as_root = not (user is not None and user != 0)

    capabilities = as_dict(own.get("capabilities"))
    added = {
        normalize_capability(c) for c in as_list(capabilities.get("add")) if isinstance(c, str)
    }
    dropped = {
        normalize_capability(c) for c in as_list(capabilities.get("drop")) if isinstance(c, str)
    }
    return EffectiveContext(
        privileged=as_bool(own.get("privileged")) is True,
        run_as_root=run_as_root,
        allow_privilege_escalation=as_bool(own.get("allowPrivilegeEscalation")) is not False,
        writable_root_fs=as_bool(own.get("readOnlyRootFilesystem")) is not True,
        drops_all_capabilities="ALL" in dropped,
        dangerous_capabilities=tuple(sorted(added & DANGEROUS_CAPABILITIES)),
        seccomp_type=_seccomp_type(own) or _seccomp_type(pod_context),
        has_security_context=bool(own) or bool(pod_context),
        run_as_user=user,
        run_as_non_root=non_root,
    )


# ---------------------------------------------------------------------------------------
# Images, resources, probes, ports
# ---------------------------------------------------------------------------------------


def image_of(container: dict[str, Any]) -> str:
    """The image reference as text; empty for a null or missing ``image``."""
    image = container.get("image")
    return image.strip() if isinstance(image, str) else ""


def uses_floating_tag(image: str) -> bool:
    """True when the image is untagged or tagged with a moving tag and is not digest-pinned.

    An empty image, an unresolved Helm placeholder and a reference that is only a variable are
    unknown rather than floating, so none of them counts.
    """
    if not image or PLACEHOLDER_PREFIX in image:
        return False
    ref = parse_image_ref(image)
    if ref.digest:
        return False
    if ref.kind == "variable" and not ref.tag:
        return False
    return is_floating_tag(ref.tag)


def _limit_set(limits: dict[str, Any], resource: str) -> bool:
    value = limits.get(resource)
    return value is not None and str(value).strip() != ""


def _has_secret_env(container: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for entry in as_list(container.get("env")):
        if isinstance(entry, dict) and "secretKeyRef" in as_dict(entry.get("valueFrom")):
            name = entry.get("name")
            names.append(name if isinstance(name, str) else "")
    return names


def _uses_host_port(container: dict[str, Any]) -> bool:
    return any(isinstance(p, dict) and p.get("hostPort") for p in as_list(container.get("ports")))


# ---------------------------------------------------------------------------------------
# One aggregation rule
# ---------------------------------------------------------------------------------------


def _names(views: list[ContainerView], keep: list[bool]) -> list[str]:
    return sorted({view.name for view, flag in zip(views, keep) if flag})


def security_properties(pod_spec: dict[str, Any]) -> dict[str, Any]:
    """The security-relevant properties of a workload's pod spec.

    The property names are the ones the rules read. ``container_findings`` maps a property
    name to the containers that make it unsafe, for attribution in descriptions.
    """
    pod_context = as_dict(pod_spec.get("securityContext"))
    views = container_views(pod_spec)
    contexts = [effective_context(v.spec, pod_context) for v in views]
    ongoing = [v.runs_continuously for v in views]
    images = [image_of(v.spec) for v in views]

    findings: dict[str, list[str]] = {}

    def record(flag: str, bad: list[bool]) -> bool:
        """Remember the containers that are bad for ``flag``; True when there is any."""
        names = _names(views, bad)
        if names:
            findings[flag] = names
        return bool(names)

    def judged(flags: list[bool], only_ongoing: bool) -> list[bool]:
        """Mask a per-container list to the containers the check applies to."""
        if not only_ongoing:
            return flags
        return [flag and run for flag, run in zip(flags, ongoing)]

    privileged = record("privileged", [c.privileged for c in contexts])
    run_as_root = record("run_as_root", [c.run_as_root for c in contexts])
    escalation = record(
        "allow_privilege_escalation", [c.allow_privilege_escalation for c in contexts]
    )
    writable = record("writable_root_fs", [c.writable_root_fs for c in contexts])
    not_dropped = record("capabilities_dropped", [not c.drops_all_capabilities for c in contexts])
    record("dangerous_capabilities", [bool(c.dangerous_capabilities) for c in contexts])
    no_security_context = record(
        "has_security_context", [not c.has_security_context for c in contexts]
    )
    floating = record("uses_latest_tag", [uses_floating_tag(image) for image in images])
    host_port = record("has_host_port", [_uses_host_port(v.spec) for v in views])

    seccomp_types = [c.seccomp_type for c in contexts]
    if views:
        record(
            "has_seccomp_profile", [t not in ("RuntimeDefault", "Localhost") for t in seccomp_types]
        )
        seccomp = _worst_seccomp(seccomp_types)
    else:
        seccomp = _seccomp_type(pod_context)

    def limits(view: ContainerView) -> dict[str, Any]:
        return as_dict(as_dict(view.spec.get("resources")).get("limits"))

    no_cpu = record(
        "has_cpu_limit", judged([not _limit_set(limits(v), "cpu") for v in views], True)
    )
    no_memory = record(
        "has_memory_limit", judged([not _limit_set(limits(v), "memory") for v in views], True)
    )
    no_storage = record(
        "has_ephemeral_storage_limit",
        judged([not _limit_set(limits(v), "ephemeral-storage") for v in views], True),
    )
    record(
        "has_resource_limits",
        judged(
            [not (_limit_set(limits(v), "cpu") and _limit_set(limits(v), "memory")) for v in views],
            True,
        ),
    )
    no_liveness = record(
        "has_liveness_probe", judged([not v.spec.get("livenessProbe") for v in views], True)
    )
    no_readiness = record(
        "has_readiness_probe", judged([not v.spec.get("readinessProbe") for v in views], True)
    )

    secret_env = sorted({name for v in views for name in _has_secret_env(v.spec)})
    record("secret_env_vars", [bool(_has_secret_env(v.spec)) for v in views])

    dangerous = sorted({cap for c in contexts for cap in c.dangerous_capabilities})
    return {
        "privileged": privileged,
        "run_as_root": run_as_root,
        "allow_privilege_escalation": escalation,
        "writable_root_fs": writable,
        "capabilities_dropped": not not_dropped,
        "dangerous_capabilities": dangerous,
        "has_security_context": not no_security_context,
        "seccomp_profile_type": seccomp,
        "has_seccomp_profile": seccomp in ("RuntimeDefault", "Localhost"),
        "uses_latest_tag": floating,
        "has_host_port": host_port,
        "secret_env_vars": secret_env,
        "has_cpu_limit": not no_cpu,
        "has_memory_limit": not no_memory,
        "has_ephemeral_storage_limit": not no_storage,
        "has_resource_limits": not (no_cpu or no_memory),
        "has_liveness_probe": not no_liveness,
        "has_readiness_probe": not no_readiness,
        "images": sorted({image for image in images if image}),
        "container_findings": dict(sorted(findings.items())),
    }


# Worst first: a profile that is off beats a missing one, which beats a custom one
_SECCOMP_BADNESS = ("Unconfined", None, "Localhost", "RuntimeDefault")


def _worst_seccomp(types: list[str | None]) -> str | None:
    """The seccomp type that describes the weakest container."""
    present = set(types)
    for candidate in _SECCOMP_BADNESS:
        if candidate in present:
            return candidate
    # Any other spelling is not one of the three the API defines; the first one stands
    return next(iter(sorted(t for t in present if t is not None)), None)


def pod_properties(pod_spec: dict[str, Any]) -> dict[str, Any]:
    """Properties of the pod spec itself: host namespaces, service account, volumes, context."""
    props: dict[str, Any] = {
        "host_network": as_bool(pod_spec.get("hostNetwork")) is True,
        "host_pid": as_bool(pod_spec.get("hostPID")) is True,
        "host_ipc": as_bool(pod_spec.get("hostIPC")) is True,
    }
    account = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
    props["service_account_name"] = account if isinstance(account, str) and account else "default"
    automount = as_bool(pod_spec.get("automountServiceAccountToken"))
    # Kubernetes mounts the token unless something says otherwise
    props["automount_sa_token"] = True if automount is None else automount
    props["pod_automount_sa_token"] = automount
    props["has_host_path_volume"] = any(
        isinstance(volume, dict) and "hostPath" in volume
        for volume in as_list(pod_spec.get("volumes"))
    )
    pod_context = as_dict(pod_spec.get("securityContext"))
    props["pod_run_as_non_root"] = pod_context.get("runAsNonRoot")
    props["pod_run_as_user"] = pod_context.get("runAsUser")
    return props
