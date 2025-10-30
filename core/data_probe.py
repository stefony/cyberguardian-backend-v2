# core/data_probe.py
"""
Small helper to inspect the presence/size/line-count of the training data file.

- Uses env CG_TRAINING_PATH if set
- Fallbacks: data/training_logs.jsonl and data/training_logs.jsonl.gz
- Returns a compact dict safe to embed in API responses
"""

from __future__ import annotations
import os
import gzip
from typing import Dict, Optional

DEFAULT_CANDIDATES = [
    os.getenv("CG_TRAINING_PATH"),               # explicit env override
    "data/training_logs.jsonl",                  # plain jsonl
    "data/training_logs.jsonl.gz",               # gzipped jsonl
]

def _count_lines(path: str, gz: bool) -> int:
    if gz:
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    else:
        with open(path, "rt", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)

def probe_training_file() -> Dict[str, Optional[object]]:
    """
    Returns:
      {
        "present": bool,
        "path": str | None,
        "size_bytes": int | None,
        "line_count": int | None,
        "error": str | None
      }
    """
    # normalize candidates (strip Nones)
    candidates = [p for p in DEFAULT_CANDIDATES if p]
    result: Dict[str, Optional[object]] = {
        "present": False,
        "path": None,
        "size_bytes": None,
        "line_count": None,
        "error": None,
    }

    for path in candidates:
        try:
            if not os.path.exists(path):
                continue
            size = os.path.getsize(path)
            gz = path.endswith(".gz")
            lines = _count_lines(path, gz)
            result.update(
                present=True,
                path=path,
                size_bytes=int(size),
                line_count=int(lines),
                error=None,
            )
            return result
        except Exception as e:
            # try next candidate but keep last error
            result.update(error=str(e), path=path)

    # nothing found
    return result
