"""Custom exceptions for the dot-quote extractor."""

from __future__ import annotations


class FileProcessingError(Exception):
    """Raised when an input file cannot be opened or read.

    Attributes:
        path: The path to the failing file.
        reason: Human-readable reason for failure.
    """

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason