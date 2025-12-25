"""Core streaming extractor for the pattern: open=`"` and close=`."`.

Fix: if we see a bare double-quote (") while capturing and it is NOT the
second character of a valid closer (."), we discard the current capture
as invalid and restart from this new quote. This ensures we always pair
the nearest opener with the nearest `."` closer and avoids swallowing
unwanted text between a bad opener (e.g., `?"`) and a distant `."`.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Iterable, Iterator, List, Sequence, TextIO

from .exceptions import FileProcessingError

logger = logging.getLogger(__name__)


class DotQuoteExtractor:
    """Extractor for `"` ... `."` segments.

    Attributes:
        include_incomplete: If True, emits the trailing collected text at EOF
            even if a closing `."` was not encountered.
    """

    def __init__(self, include_incomplete: bool = False) -> None:
        self.include_incomplete: bool = include_incomplete

    def extract_from_string(self, text: str) -> List[str]:
        """Extract all `"` ... `."` segments from an in-memory string.

        Args:
            text: Input text.

        Returns:
            Ordered list of extracted segments, excluding delimiters.
        """
        return list(self._extract_stream(io.StringIO(text)))

    def extract_from_file(self, path: Path, encodings: Sequence[str] | None = None) -> List[str]:
        """Extract segments from a file, trying a few common encodings.

        Args:
            path: Path to a text file.
            encodings: Ordered encodings to try; defaults provided.

        Returns:
            Extracted segments.

        Raises:
            FileProcessingError: If the file is unreadable with provided encodings.
        """
        if encodings is None:
            encodings = ("utf-8", "utf-8-sig", "cp1252", "latin-1")

        last_exc: Exception | None = None
        for enc in encodings:
            try:
                logger.debug("Opening %s with encoding=%s", path, enc)
                with path.open("r", encoding=enc, errors="strict", newline="") as f:
                    return list(self._extract_stream(f))
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to read %s as %s: %s", path, enc, exc)
                last_exc = exc

        try:
            logger.warning("Falling back to errors='replace' for %s", path)
            with path.open("r", encoding=encodings[0], errors="replace", newline="") as f:
                return list(self._extract_stream(f))
        except Exception as exc:  # noqa: BLE001
            raise FileProcessingError(str(path), f"cannot read file: {exc}") from (last_exc or exc)

    @staticmethod
    def write_output(quotes: Iterable[str], out_path: Path, separator: str = "\n\n") -> None:
        """Write extracted segments to a file.

        Args:
            quotes: Iterable of extracted segments.
            out_path: Destination file path.
            separator: Separator string between segments (default: blank line).
        """
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8", newline="\n") as f:
            first = True
            for q in quotes:
                if not first:
                    f.write(separator)
                f.write(q)
                first = False
            f.write("\n")

    def _extract_stream(self, stream: TextIO, chunk_size: int = 65536) -> Iterator[str]:
        """Stream the text and yield each captured segment.

        Args:
            stream: Open text stream.
            chunk_size: Characters per read.

        Yields:
            Extracted segments, excluding delimiters.
        """
        in_quote = False
        buf: list[str] = []
        prev: str | None = None
        pending_dot = False  # True when we've seen '.' while inside a quote

        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break

            i = 0
            while i < len(chunk):
                ch = chunk[i]

                if not in_quote:
                    # Open only on an unescaped double-quote
                    if ch == '"' and prev != "\\":
                        logger.debug("Opening on '\"'")
                        in_quote = True
                        buf.clear()
                        pending_dot = False
                    prev = ch
                    i += 1
                    continue

                # --- In-quote ---
                if pending_dot:
                    # We saw '.', check for closing '"'
                    if ch == '"':
                        logger.debug('Closing on sequence %r%r', ".", '"')
                        yield "".join(buf)
                        in_quote = False
                        buf.clear()
                        pending_dot = False
                        prev = ch
                        i += 1
                        continue
                    else:
                        # Not a closer; commit the pending dot and current char
                        buf.append(".")
                        buf.append(ch)
                        pending_dot = False
                        prev = ch
                        i += 1
                        continue

                # No pending dot
                if ch == ".":
                    pending_dot = True
                    prev = ch
                    i += 1
                    continue

                if ch == '"' and prev != "\\":
                    # Bare quote while capturing and not a `."` closer:
                    # The previous opener didn't lead to a legal close. Restart here.
                    logger.debug("Restarting capture at a new bare quote; discarding previous buffer of %d chars", len(buf))
                    buf.clear()
                    # stay in_quote = True, pending_dot = False; this quote becomes the new opener
                    prev = ch
                    i += 1
                    continue

                # Regular character inside the capture
                buf.append(ch)
                prev = ch
                i += 1

        # EOF handling
        if in_quote:
            if pending_dot and self.include_incomplete:
                buf.append(".")
            if self.include_incomplete and buf:
                logger.debug("Emitting incomplete segment at EOF")
                yield "".join(buf)