"""Dot-Quote Extractor package.

Minimal package init to avoid pre-importing submodules when running
`python -m dq_extractor.cli`, which would otherwise populate sys.modules
and trigger runpy warnings.
"""

from __future__ import annotations

__all__ = ["__version__"]
__version__: str = "1.0.0"