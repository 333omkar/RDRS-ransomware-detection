"""Shannon entropy utilities (FR-3).

Ransomware-encrypted files look like random noise: their byte-value
distribution is close to uniform, which pushes Shannon entropy toward
its maximum of 8 bits/byte. Plain text and most normal documents sit
well below that.
"""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

SAMPLE_BYTES = 64 * 1024  # 64 KB — enough to characterize a file, fast on big files


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of `data` in bits per byte, range [0, 8]."""
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str | Path, sample_bytes: int = SAMPLE_BYTES) -> float | None:
    """Read up to `sample_bytes` from the start of a file and return its entropy.

    Returns None if the file can't be read (deleted mid-scan, permission
    denied, etc.) so callers can skip gracefully rather than crash.
    """
    p = Path(path)
    try:
        with p.open("rb") as f:
            data = f.read(sample_bytes)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None
    return shannon_entropy(data)
