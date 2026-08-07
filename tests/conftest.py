"""Fake cho toàn bộ phụ thuộc ngoài. Không cần mạng, không cần API key."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from idp_review.checkpoint import memory_checkpointer
from idp_review.clients.principles import FilePrincipleStore
from idp_review.clients.repo import LocalRepoClient
from idp_review.clients.scanner import RegexScanner
from idp_review.clients.sink import MemorySink
from idp_review.deps import Deps
from idp_review.graph import build_review_graph
from idp_review.state import Finding

ROOT = Path(__file__).resolve().parents[1]
# Dataset smoke đi kèm engine: giữ cho pytest chạy offline. Benchmark thật nằm
# ở repo data riêng và chỉ được nạp bởi run_eval.py.
CASE = ROOT / "tests" / "fixtures" / "smoke-system"


class FakeLLM:
    """Có chủ đích sinh cả finding tốt lẫn finding bịa.

    Fake mà lúc nào cũng ngoan thì bộ test không chứng minh được gì về an toàn.
    """

    def __init__(self, request_out_of_scope: bool = False):
        self.request_out_of_scope = request_out_of_scope
        self.plan_calls = 0

    def plan_evidence(self, ctx):
        self.plan_calls += 1
        reqs = [{"service_key": "payment-api", "path": "Dockerfile", "why": "kiểm tra USER"},
                {"service_key": "payment-api", "path": "k8s/deploy.yaml", "why": "replicas"}]
        if self.request_out_of_scope:
            reqs.append({"service_key": "ledger-api", "path": "Dockerfile", "why": "so sánh"})
        return reqs

    def analyze(self, axis, ctx):
        if axis != "security" or not ctx["evidence"]:
            return []
        real_ev = ctx["evidence"][0]["id"]
        real_p = ctx["principles"][0]["id"] if ctx["principles"] else "P-SEC-001"
        return [
            Finding(id="F-good", axis="security", title="Container chạy bằng root",
                    service_key="payment-api", evidence_ids=[real_ev],
                    principle_ids=[real_p], severity=4, confidence=0.9),
            Finding(id="F-fake-evidence", axis="security", title="Secret hardcode",
                    service_key="payment-api", evidence_ids=["ev-khong-ton-tai"],
                    principle_ids=[real_p], severity=5, confidence=0.9),
            Finding(id="F-fake-principle", axis="security", title="Sai chuẩn nội bộ",
                    service_key="payment-api", evidence_ids=[real_ev],
                    principle_ids=["P-BIA-999"], severity=5, confidence=0.9),
            Finding(id="F-no-anchor", axis="security", title="Cảm giác không an toàn",
                    service_key="payment-api", severity=5, confidence=0.9),
        ]

    def compose(self, findings):
        return {"summary": f"{len(findings)} finding", "top_risks": []}


class StubOpenAI:
    """Giả lập SDK OpenAI ở tầng chat.completions.create, không chạm mạng."""

    def __init__(self, payload: dict, refusal: str | None = None):
        self.payload, self.refusal, self.calls = payload, refusal, []
        outer = self

        class _Msg:
            content = json.dumps(outer.payload, ensure_ascii=False)
            refusal = outer.refusal

        class _Completions:
            def create(self, **kw):
                outer.calls.append(kw)
                return type("R", (), {
                    "choices": [type("C", (), {"message": _Msg()})()],
                    "usage": type("U", (), {"prompt_tokens": 10, "completion_tokens": 5})(),
                })()

        self.chat = type("Chat", (), {"completions": _Completions()})()


@pytest.fixture
def principles():
    return FilePrincipleStore(ROOT / "principles" / "principles.yaml")


@pytest.fixture
def sink():
    return MemorySink()


@pytest.fixture
def deps_factory(principles, sink):
    def make(scope=None, code_readable=None, llm=None):
        repo = LocalRepoClient(CASE, scope=scope,
                               code_readable=code_readable or ["payment-api"])
        return Deps(repo=repo, llm=llm or FakeLLM(), principles=principles,
                    scanner=RegexScanner(), sink=sink)
    return make


@pytest.fixture
def run_graph(deps_factory):
    def run(scope=None, code_readable=None, llm=None, review_id="r-1"):
        graph = build_review_graph(checkpointer=memory_checkpointer())
        config = {"configurable": {"thread_id": review_id,
                                   "deps": deps_factory(scope, code_readable, llm)}}
        state = graph.invoke(
            {"review_id": review_id, "commit_sha": "HEAD", "actor_token": "tok"}, config)
        return graph, config, state
    return run
