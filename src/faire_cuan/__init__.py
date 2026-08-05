class OciVerifyError(Exception):
    """Base error for oci-verify-import operations."""


class ValidationError(OciVerifyError):
    """Input validation failures (not digest-pinned, wrong key count)."""


class VerificationError(OciVerifyError):
    """Cosign signature verification failure."""


class ToolError(OciVerifyError):
    """External tool invocation failure."""
