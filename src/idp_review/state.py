"""Kiểu dữ liệu dùng chung cho toàn bộ graph."""

from __future__ import annotations

import operator
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, Field

Axis = Literal["security", "availability", "scalability", "cost"]
AXES: tuple[Axis, ...] = ("security", "availability", "scalability", "cost")

Origin = Literal["graph_rule", "scanner", "llm"]


class Evidence(BaseModel):
    """Một mẩu bằng chứng neo được về mã nguồn tại đúng một commit."""

    id: str
    service_key: str
    path: str
    start_line: int = 1
    end_line: int = 1
    content: str = ""
    blob_sha: str = ""
    source: Literal["repo", "scanner", "ast_grep"] = "repo"


class Finding(BaseModel):
    id: str
    axis: Axis
    title: str
    service_key: str
    detail: str = ""

    # Neo bắt buộc với finding do LLM sinh — verify đối chiếu hai list này
    evidence_ids: list[str] = Field(default_factory=list)
    principle_ids: list[str] = Field(default_factory=list)

    origin: Origin = "llm"
    rule_id: str | None = None
    severity: int = 3          # 1..5 — LLM đề xuất
    blast_radius: int = 0      # networkx tính, KHÔNG do LLM
    confidence: float = 0.5
    priority: float = 0.0      # tính bằng code ở score_and_rank
    tradeoff: str | None = None

    def haystack(self) -> str:
        """Chuỗi dùng để đối chiếu với ground truth trong benchmark."""
        return f"{self.title} {self.detail} {self.rule_id or ''}".lower()


class ReviewState(TypedDict, total=False):
    review_id: str
    commit_sha: str
    actor_token: str              # KHÔNG log, KHÔNG đưa vào prompt

    scope: list[str]              # được xem metadata
    code_readable: list[str]      # được đọc code (tập con của scope)

    catalog: dict[str, dict]
    graph_json: dict
    blast_radius: dict[str, int]

    evidence: Annotated[list[Evidence], operator.add]
    evidence_requests: list[dict]
    evidence_tokens: int
    iteration: int

    principles: list[dict]

    raw_findings: Annotated[list[Finding], operator.add]
    findings: list[Finding]
    rejected: list[Finding]
    report: dict | None
    persisted: bool

    errors: Annotated[list[str], operator.add]
