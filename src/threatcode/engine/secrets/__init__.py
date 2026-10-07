"""Secret detection: the detector core and its placement on the resources of a scan."""

from threatcode.engine.secrets.config import SecretScanConfig
from threatcode.engine.secrets.scanner import SecretScanner

__all__ = ["SecretScanConfig", "SecretScanner"]
