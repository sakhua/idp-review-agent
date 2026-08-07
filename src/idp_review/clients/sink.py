"""Sink ghi kết quả ra JSON. Thay bằng Postgres khi lên production."""

from __future__ import annotations

import json
from pathlib import Path

from ..state import Finding


class JsonSink:
    def __init__(self, out_dir: str | Path = "runs"):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.last: dict | None = None

    def save(self, review_id: str, findings: list[Finding],
             rejected: list[Finding]) -> None:
        # Lưu cả `rejected`: đó là dữ liệu đo tỉ lệ bịa của model theo thời gian.
        payload = {
            "review_id": review_id,
            "findings": [f.model_dump() for f in findings],
            "rejected": [f.model_dump() for f in rejected],
        }
        self.last = payload
        (self.out_dir / f"{review_id}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class MemorySink:
    def __init__(self):
        self.saved: list[dict] = []

    def save(self, review_id, findings, rejected):
        self.saved.append({"review_id": review_id,
                           "findings": findings, "rejected": rejected})
