"""Command-line interface for the dot-quote extractor."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Sequence

from .exceptions import FileProcessingError
from .extractor import DotQuoteExtractor

LOG_FORMAT = "%(levelname)s %(name)s: %(message)s"
logger = logging.getLogger(__name__)


def configure_logging(verbose: bool) -> None:
    """Configure root logger based on verbosity."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format=LOG_FORMAT)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse CLI arguments."""
    p = argparse.ArgumentParser(
        prog="dq-extractor",
        description='Extract text between `"` and `."` from files.',
    )
    p.add_argument("path", help="Path to a .txt file or a directory of .txt files.")
    p.add_argument("-r", "--recursive", action="store_true", help="Recurse into subdirectories (when PATH is a directory).")
    p.add_argument("-p", "--pattern", action="append", default=["*.txt"], help="Glob pattern(s) for files (default: *.txt).")
    p.add_argument("-o", "--out-dir", type=str, default=None, help="Output directory (default: alongside file, or extracted_quotes under directory).")
    p.add_argument("--include-incomplete", action="store_true", help="Emit trailing incomplete capture at EOF if no closing `.\"`.")
    p.add_argument("--no-blank-line", action="store_true", help="Do not insert a blank line between extracted segments.")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return p.parse_args(argv)


def discover_files(target: Path, patterns: Sequence[str], recursive: bool) -> List[Path]:
    """Find files to process based on the target path and glob patterns."""
    if target.is_file():
        return [target]
    files: list[Path] = []
    if recursive:
        for pat in patterns:
            files.extend(target.rglob(pat))
    else:
        for pat in patterns:
            files.extend(target.glob(pat))
    # Normalize and sort for determinism
    return sorted({p for p in files if p.is_file()})


def default_out_path(input_file: Path, root: Path | None) -> Path:
    """Compute where to write the output for an input file."""
    if root is None:
        return input_file.with_suffix(input_file.suffix + ".quotes.txt")
    return root / f"{input_file.stem}.quotes.txt"


def run(argv: Sequence[str]) -> int:
    """Entry point for tests and python -m usage.

    Skips creating an output file when a source file yields zero segments.
    """
    args = parse_args(argv)
    configure_logging(args.verbose)

    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        logger.error("Path not found: %s", target)
        return 2

    out_root = None
    if target.is_dir():
        out_root = Path(args.out_dir).expanduser().resolve() if args.out_dir else target / "extracted_quotes"
    elif args.out_dir:
        out_root = Path(args.out_dir).expanduser().resolve()

    sep = "\n" if args.no_blank_line else "\n\n"
    extractor = DotQuoteExtractor(include_incomplete=args.include_incomplete)
    files = discover_files(target, args.pattern, args.recursive)

    if not files:
        logger.warning("No files matched.")
        return 0

    ok = 0
    for fpath in files:
        try:
            segments = extractor.extract_from_file(fpath)
            if not segments:
                # New behavior: do NOT create an output file for zero segments
                logger.info("No segments found in %s; skipping output file", fpath.name)
                ok += 1  # processed successfully; just nothing to write
                continue

            out_path = default_out_path(fpath, out_root)
            DotQuoteExtractor.write_output(segments, out_path, separator=sep)
            logger.info("Wrote %d segment(s) -> %s", len(segments), out_path)
            ok += 1
        except FileProcessingError as exc:
            logger.error("Failed %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error on %s: %s", fpath, exc)

    return 0 if ok == len(files) else 1


def main() -> None:
    """Console script entry point."""
    sys.exit(run(sys.argv[1:]))