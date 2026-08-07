"""Cài đặt LLMClient bằng OpenAI API, dùng Structured Outputs (strict json_schema).

Vì sao strict json_schema thay vì json_object: json_object chỉ đảm bảo cú pháp JSON
hợp lệ chứ không đảm bảo đúng schema. Strict mode ràng buộc ngay ở tầng sinh token
nên node sau không bao giờ nhận field thiếu hoặc sai kiểu.

Lưu ý về thiết kế schema: schema mà LLM thấy HẸP HƠN class Finding nội bộ.
LLM không được phép đặt blast_radius, priority hay origin — đó là những trường
do code tính. Nếu để LLM tự điền, bạn mất tính tất định của bảng xếp hạng.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI

from ..state import Finding
from .prompts import ANALYZE_SYSTEM, COMPOSE_SYSTEM, PLAN_SYSTEM

_EVIDENCE_REQUEST_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["requests"],
    "properties": {
        "requests": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["service_key", "path", "why"],
                "properties": {
                    "service_key": {"type": "string"},
                    "path": {"type": "string"},
                    "why": {"type": "string"},
                },
            },
        }
    },
}

_FINDINGS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "axis", "title", "detail", "service_key",
                             "evidence_ids", "principle_ids", "severity",
                             "confidence", "tradeoff"],
                "properties": {
                    "id": {"type": "string"},
                    "axis": {"type": "string",
                             "enum": ["security", "availability", "scalability", "cost"]},
                    "title": {"type": "string"},
                    "detail": {"type": "string"},
                    "service_key": {"type": "string"},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    "principle_ids": {"type": "array", "items": {"type": "string"}},
                    "severity": {"type": "integer"},
                    "confidence": {"type": "number"},
                    "tradeoff": {"type": ["string", "null"]},
                },
            },
        }
    },
}

_REPORT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "top_risks"],
    "properties": {
        "summary": {"type": "string"},
        "top_risks": {"type": "array", "items": {"type": "string"}},
    },
}


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0


@dataclass
class OpenAILLM:
    """Cài đặt LLMClient. Đặt OPENAI_API_KEY và OPENAI_MODEL trong .env."""

    model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-5.6"))
    temperature: float | None = None
    max_retries: int = 2
    client: Any = None
    usage: Usage = field(default_factory=Usage)

    def __post_init__(self):
        if self.client is None:
            self.client = OpenAI(
                api_key=os.getenv("OPENAI_API_KEY"),
                base_url=os.getenv("OPENAI_BASE_URL") or None,
            )

    # ── nội bộ ───────────────────────────────────────────────────────────────

    def _call(self, system: str, user: str, schema: dict, name: str) -> dict:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": name, "strict": True, "schema": schema},
            },
        }
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature

        last_err: Exception | None = None
        for _ in range(self.max_retries + 1):
            try:
                resp = self.client.chat.completions.create(**kwargs)
                msg = resp.choices[0].message
                # Structured Outputs có thêm một kiểu lỗi: model từ chối trả lời.
                # Phải kiểm tra refusal TRƯỚC khi parse, nếu không sẽ nuốt lỗi.
                if getattr(msg, "refusal", None):
                    raise ValueError(f"model từ chối: {msg.refusal}")
                if getattr(resp, "usage", None):
                    self.usage.prompt_tokens += resp.usage.prompt_tokens or 0
                    self.usage.completion_tokens += resp.usage.completion_tokens or 0
                self.usage.calls += 1
                return json.loads(msg.content)
            except Exception as exc:                      # noqa: BLE001
                last_err = exc
        raise RuntimeError(f"gọi OpenAI thất bại sau {self.max_retries + 1} lần: {last_err}")

    # ── LLMClient ────────────────────────────────────────────────────────────

    def plan_evidence(self, ctx: dict) -> list[dict]:
        user = json.dumps({
            "graph_findings": [
                {k: f[k] for k in ("rule_id", "service_key", "axis", "detail")}
                for f in ctx["graph_findings"]
            ],
            "principles": [{"id": p["id"], "text": p["text"]} for p in ctx["principles"]],
            "file_trees": ctx["trees"],
            "already_fetched": ctx["already_have"],
        }, ensure_ascii=False)
        out = self._call(PLAN_SYSTEM, user, _EVIDENCE_REQUEST_SCHEMA, "evidence_requests")
        allowed = set(ctx["trees"])
        return [r for r in out["requests"] if r["service_key"] in allowed][:12]

    def analyze(self, axis: str, ctx: dict) -> list[Finding]:
        user = json.dumps({
            "axis": axis,
            "principles": ctx["principles"],
            "evidence": [
                {"id": e["id"], "service_key": e["service_key"], "path": e["path"],
                 "lines": f"{e['start_line']}-{e['end_line']}", "content": e["content"]}
                for e in ctx["evidence"]
            ],
            "architecture_findings": [
                {k: f[k] for k in ("rule_id", "service_key", "detail")}
                for f in ctx["graph_findings"]
            ],
        }, ensure_ascii=False)
        out = self._call(ANALYZE_SYSTEM.format(axis=axis), user,
                         _FINDINGS_SCHEMA, "findings")
        # origin luôn bị ép về 'llm' — không tin field do model sinh.
        return [Finding(**{**f, "origin": "llm"}) for f in out["findings"]]

    def compose(self, findings: list[Finding]) -> dict:
        user = json.dumps(
            [{"id": f.id, "axis": f.axis, "title": f.title,
              "severity": f.severity, "blast_radius": f.blast_radius}
             for f in findings], ensure_ascii=False)
        return self._call(COMPOSE_SYSTEM, user, _REPORT_SCHEMA, "report")
