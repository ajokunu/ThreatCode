"""ThreatCode exceptions."""


class ThreatCodeError(Exception):
    """Base exception for all ThreatCode errors."""


class ParseError(ThreatCodeError):
    """Raised when IaC input cannot be parsed."""


class UnsupportedFormatError(ParseError):
    """Raised when the input format is not recognized."""


class RuleLoadError(ThreatCodeError):
    """Raised when a rule file cannot be loaded or is invalid."""


class ConfigError(ThreatCodeError):
    """Raised when configuration is invalid."""


class LLMError(ThreatCodeError):
    """Raised when LLM communication fails."""
