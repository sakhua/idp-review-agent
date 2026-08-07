"""Seam dependency injection.

Mọi phụ thuộc ngoài (repo, LLM, RAG, scanner, sink) đi qua `Deps` truyền bằng
config["configurable"]["deps"]. Đây là điểm duy nhất test cần thay thế.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .state import Evidence, Finding


class RepoClient(Protocol):
    """Nguồn code + catalog. Cài đặt bằng GitLab API, git clone, hay thư mục local."""

    def accessible_projects(self, token: str) -> list[str]: ...
    def can_read_code(self, token: str, service_key: str) -> bool: ...
    def read_catalog(self, service_key: str, ref: str) -> dict | None: ...
    def list_tree(self, service_key: str, ref: str) -> list[str]: ...
    def read_file(self, service_key: str, path: str, ref: str) -> dict | None: ...


class LLMClient(Protocol):
    def plan_evidence(self, ctx: dict) -> list[dict]: ...
    def analyze(self, axis: str, ctx: dict) -> list[Finding]: ...
    def compose(self, findings: list[Finding]) -> dict: ...


class PrincipleStore(Protocol):
    def search(self, rule_ids: list[str], axes: list[str]) -> list[dict]: ...


class Scanner(Protocol):
    def scan(
        self, service_key: str, files: list[dict]
    ) -> tuple[list[Evidence], list[Finding]]: ...


class Sink(Protocol):
    def save(
        self, review_id: str, findings: list[Finding], rejected: list[Finding]
    ) -> None: ...


@dataclass
class Deps:
    repo: RepoClient
    llm: LLMClient
    principles: PrincipleStore
    scanner: Scanner
    sink: Sink


def get_deps(config: dict[str, Any]) -> Deps:
    return config["configurable"]["deps"]
