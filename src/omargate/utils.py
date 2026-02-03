from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path) -> str:
    return sha256_hex(path.read_bytes())

def json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)

def safe_read_text(path: Path, max_bytes: int = 5_000_000) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError(f"File too large: {path} ({len(data)} bytes)")
    return data.decode("utf-8", errors="replace")
