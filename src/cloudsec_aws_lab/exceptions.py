from __future__ import annotations


class CloudSecLabError(Exception):
    """Base exception for user-facing analyzer errors."""


class InputValidationError(CloudSecLabError):
    """Raised when an input file is missing, unsafe, too large, or malformed."""
