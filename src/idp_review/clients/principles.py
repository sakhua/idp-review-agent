"""PrincipleStore đọc từ file YAML, khớp bằng keyword.

Bản tối giản có chủ đích: với vài chục nguyên tắc nội bộ thì keyword matching
đủ dùng và tất định. Chỉ chuyển sang vector DB khi tập nguyên tắc lớn tới mức
keyword bắt đầu bỏ sót — đừng thêm embedding chỉ vì nó nghe hiện đại hơn.
"""

from __future__ import annotations

from pathlib import Path

import yaml


class FilePrincipleStore:
    def __init__(self, path: str | Path = "principles/principles.yaml"):
        self.items: list[dict] = yaml.safe_load(Path(path).read_text(encoding="utf-8"))

    def search(self, rule_ids: list[str], axes: list[str]) -> list[dict]:
        wanted = set(axes)
        return [p for p in self.items if p.get("axis") in wanted]

    def by_id(self, pid: str) -> dict | None:
        return next((p for p in self.items if p["id"] == pid), None)
