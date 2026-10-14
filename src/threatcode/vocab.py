"""Shared vocabulary for rules and for the parts of the engine that reason like them.

Keeping the lists in one place means a rule, the exposure logic and a parser cannot
disagree about what "the whole internet" or "an admin port" means.
"""

from __future__ import annotations

# Sources that mean "anyone": CIDRs, the Azure and GCP keywords, and a bare wildcard.
# Compared case-insensitively; use is_world_source() rather than a raw membership test.
WORLD_SOURCES: frozenset[str] = frozenset({"0.0.0.0/0", "::/0", "*", "internet", "any"})

# Ports that give a remote administrator a shell or a management plane.
ADMIN_PORTS: frozenset[int] = frozenset({22, 23, 3389, 5985, 5986})

# Default ports of databases, caches and search engines that should never face the internet.
DATABASE_PORTS: frozenset[int] = frozenset(
    {1433, 1521, 3306, 5432, 5984, 6379, 7000, 7001, 9042, 9200, 9300, 11211, 27017}
)

# Linux capabilities that let a container act on the host or on other containers.
DANGEROUS_CAPABILITIES: frozenset[str] = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_RAWIO",
        "SYS_BOOT",
        "BPF",
        "PERFMON",
        "NET_ADMIN",
        "NET_RAW",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
        "MKNOD",
        "SETUID",
        "SETGID",
        "CHOWN",
    }
)


def is_world_source(value: object) -> bool:
    """True when ``value`` is one of WORLD_SOURCES, ignoring case and outer whitespace."""
    return isinstance(value, str) and value.strip().lower() in WORLD_SOURCES


def normalize_capability(name: str) -> str:
    """Upper-case a capability name and drop a leading ``CAP_``.

    ``cap_net_admin`` becomes ``NET_ADMIN``, so Docker and Kubernetes spellings compare equal.
    """
    normalized = name.strip().upper()
    return normalized.removeprefix("CAP_")
