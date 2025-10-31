# core/feedback_store.py
import json, os
from datetime import datetime
from typing import Dict, Any

DATA_DIR = os.getenv("ML_DATA_DIR", "data")
LABELS_PATH = os.path.join(DATA_DIR, "labeled_logs.jsonl")

def _ensure_paths() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(LABELS_PATH):
        # създаваме празен JSONL файл
        with open(LABELS_PATH, "w", encoding="utf-8") as f:
            pass

def append_label(example: Dict[str, Any], label: str, notes: str | None = None) -> None:
    """
    Добавя един етикетиран запис към labeled_logs.jsonl (append-only).
    example: оригиналният лог (timestamp, ip, port, payload, ...).
    label: 'benign' | 'malicious' | 'suspicious' (или твои етикети).
    notes: по избор – кратък коментар от анализатор/система.
    """
    _ensure_paths()
    rec = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "label": label,
        "notes": notes,
        "example": example,
    }
    with open(LABELS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def stats() -> dict:
    """
    Бърза статистика – брой записи по етикет.
    """
    _ensure_paths()
    counts: Dict[str, int] = {}
    total = 0
    with open(LABELS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                lbl = obj.get("label", "unknown")
                counts[lbl] = counts.get(lbl, 0) + 1
                total += 1
            except Exception:
                continue
    return {"total": total, "by_label": counts, "path": LABELS_PATH}

