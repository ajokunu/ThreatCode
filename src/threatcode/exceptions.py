"""ThreatCode exceptions."""


class ThreatCodeError(Exception):
    """Base exception for all ThreatCode errors."""


class ParseError(ThreatCodeError):
    """Raised when IaC input cannot be parsed.

    ``file`` names the file inside a unit that holds several (a Terraform module is a directory of
    ``.tf`` files), as a name relative to the unit, when the parser knows it.
    """

    def __init__(self, message: str = "", *, file: str = "") -> None:
        super().__init__(message)
        self.file = file


class UnsupportedFormatError(ParseError):
    """Raised when the input format is not recognized."""


class RuleLoadError(ThreatCodeError):
    """Raised when a rule file cannot be loaded or is invalid."""


class ConfigError(ThreatCodeError):
    """Raised when configuration is invalid."""


class LLMError(ThreatCodeError):
    """Raised when LLM communication fails."""


class UsageError(ThreatCodeError):
    """Raised when the command line or a named input file is unusable.

    The CLI reports it as ``Error: <message>`` and exits 2, like any other usage error.
    """
