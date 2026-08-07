"""Chạy: pytest -v

Năm nhóm test, xếp theo giá trị:
  1. Bảo mật phạm vi   — quan trọng nhất, viết trước khi có tính năng
  2. Chống bịa         — verify phải loại finding không neo được
  3. Tính tất định     — cùng input phải cho cùng kết quả qua mọi PYTHONHASHSEED
  4. Graph end-to-end  — vòng lặp bằng chứng, interrupt, resume
  5. Client OpenAI     — schema và xử lý refusal, không chạm mạng
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from langgraph.types import Command

from conftest import CASE, ROOT, FakeLLM, StubOpenAI
from idp_review.clients.openai_llm import OpenAILLM
from idp_review.clients.repo import LocalRepoClient
from idp_review.graph import (
    MAX_EVIDENCE_ITERATIONS,
    build_graph,
    route_after_evidence,
    score_and_rank,
    verify,
)
from idp_review.state import Evidence, Finding


# ── 1. Bảo mật phạm vi ───────────────────────────────────────────────────────

def test_khong_lay_evidence_ngoai_pham_vi_du_llm_co_xin(run_graph):
    """LLM xin file ngoài quyền -> collect_evidence phải bỏ request đó.

    Test quan trọng nhất trong file: kiểm tra tính chất an toàn, không phải hành vi.
    """
    _, _, state = run_graph(code_readable=["payment-api"],
                            llm=FakeLLM(request_out_of_scope=True))
    assert {e.service_key for e in state["evidence"]} == {"payment-api"}
    assert any("ngoài phạm vi" in e for e in state["errors"])


def test_khong_co_quyen_thi_dung_ngay(run_graph):
    _, _, state = run_graph(scope=[], code_readable=[])
    assert "catalog" not in state


def test_duong_dan_luon_la_posix():
    """Chốt chặn lỗi Windows: list_tree trả "k8s\\deploy.yaml" thì mọi luật
    scanner chứa "k8s/" câm lặng không khớp, và bạn tưởng là model kém."""
    tree = LocalRepoClient(CASE).list_tree("payment-api", "HEAD")
    assert not any("\\" in p for p in tree), tree
    assert "k8s/deploy.yaml" in tree


def test_scanner_bat_duoc_luat_dang_thieu(run_graph):
    """K8S-NO-PROBE và K8S-NO-RESOURCES khớp theo path regex có "k8s/"."""
    _, _, state = run_graph(code_readable=["payment-api"])
    rules = {f.rule_id for f in state["findings"] if f.origin == "scanner"}
    assert {"K8S-NO-PROBE", "K8S-NO-RESOURCES"} <= rules, rules


def test_chan_path_traversal():
    repo = LocalRepoClient(CASE)
    assert repo.read_file("payment-api", "../../../etc/passwd", "HEAD") is None
    assert repo.read_file("payment-api", "Dockerfile", "HEAD") is not None


# ── 2. Chống bịa ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("fid", ["F-fake-evidence", "F-fake-principle", "F-no-anchor"])
def test_verify_loai_finding_bia(run_graph, fid):
    _, _, state = run_graph()
    assert fid in {f.id for f in state["rejected"]}
    assert fid not in {f.id for f in state["findings"]}


def test_verify_giu_finding_neo_dung(run_graph):
    _, _, state = run_graph()
    assert "F-good" in {f.id for f in state["findings"]}


def test_verify_khong_doi_evidence_o_finding_tat_dinh():
    state = {"raw_findings": [
        Finding(id="R1", axis="availability", title="SPOF",
                service_key="payment-api", origin="graph_rule"),
        Finding(id="L1", axis="security", title="Bịa",
                service_key="payment-api", origin="llm")],
        "evidence": [], "principles": [], "scope": ["payment-api"]}
    out = verify(state, None)
    assert [f.id for f in out["findings"]] == ["R1"]
    assert [f.id for f in out["rejected"]] == ["L1"]


# ── 3. Tính tất định ─────────────────────────────────────────────────────────

def test_build_graph_phat_hien_luat_do_thi(run_graph):
    _, _, state = run_graph()
    rules = {f.rule_id for f in state["findings"] + state["rejected"] if f.rule_id}
    assert {"ARCH-OWNER-001", "ARCH-CYCLE-001", "ARCH-SHARED-DB-001"} <= rules


@pytest.mark.parametrize("seed", ["1", "2", "7"])
def test_luat_do_thi_on_dinh_qua_moi_hash_seed(seed):
    """nx.simple_cycles trả về chu trình bắt đầu từ node tuỳ hash seed.

    Không chuẩn hoá thì service_key của finding đổi giữa các lần chạy và mọi
    phép đo eval trở nên nhiễu. Test này giữ cho lỗi đó không quay lại.
    """
    code = (
        "import sys; sys.path.insert(0, 'src');"
        "from idp_review.clients.repo import LocalRepoClient;"
        "from idp_review.graph import build_graph;"
        f"r = LocalRepoClient({str(CASE)!r});"
        "cat = {k: r.read_catalog(k, 'HEAD') for k in r.scope};"
        "print(sorted(f.id for f in build_graph({'catalog': cat}, None)['raw_findings']))"
    )
    # PHẢI kế thừa os.environ. Thay sạch env sẽ giết subprocess trên Windows
    # (thiếu SYSTEMROOT, PATH...) và test fail với stdout rỗng, che mất lỗi thật.
    env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONIOENCODING": "utf-8"}
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True,
                         text=True, env=env)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == (
        "['ARCH-CYCLE-001:ledger-api', 'ARCH-OWNER-001:payment-api', "
        "'ARCH-SHARED-DB-001:pay.payment-postgres']")


def test_blast_radius_dung_chieu():
    """Cạnh là dependent -> dependency, nên blast radius = ancestors."""
    cat = {
        "svc-a": {"spec": {"type": "service", "id": "svc-a", "owners": {"members": []},
                           "topology": [{"ref": "resource:pay/db"}]}},
        "svc-b": {"spec": {"type": "service", "id": "svc-b", "owners": {"members": []},
                           "topology": [{"ref": "resource:pay/db"}]}},
    }
    out = build_graph({"catalog": cat}, None)
    assert out["blast_radius"]["pay.db"] == 2
    assert out["blast_radius"]["svc-a"] == 0


def test_score_and_rank_on_dinh():
    findings = [Finding(id="A", axis="cost", title="a", service_key="s1",
                        severity=3, confidence=1.0),
                Finding(id="B", axis="cost", title="b", service_key="s2",
                        severity=3, confidence=1.0)]
    state = {"findings": findings, "blast_radius": {"s1": 0, "s2": 5}}
    out = score_and_rank(state, None)["findings"]
    assert [f.id for f in out] == ["B", "A"]
    assert out[0].priority == 18.0


# ── 4. Graph end-to-end ──────────────────────────────────────────────────────

def test_vong_lap_dung_khi_khong_con_file_moi():
    state = {"iteration": 1, "evidence_tokens": 0,
             "evidence_requests": [{"service_key": "payment-api", "path": "Dockerfile"}],
             "evidence": [Evidence(id="e1", service_key="payment-api", path="Dockerfile")]}
    assert route_after_evidence(state) != "plan_evidence"


def test_vong_lap_dung_khi_qua_so_lan():
    state = {"iteration": MAX_EVIDENCE_ITERATIONS, "evidence_tokens": 0,
             "evidence_requests": [{"service_key": "payment-api", "path": "moi.py"}],
             "evidence": []}
    assert route_after_evidence(state) != "plan_evidence"


def test_graph_dung_o_human_review(run_graph):
    _, _, state = run_graph()
    assert "__interrupt__" in state
    assert state["__interrupt__"][0].value["review_id"] == "r-1"


def test_resume_chi_giu_finding_duoc_duyet(run_graph, sink):
    graph, config, state = run_graph()
    ids = [f["id"] for f in state["__interrupt__"][0].value["findings"]]
    final = graph.invoke(Command(resume={"accepted": ids[:2]}), config)
    assert final["persisted"] is True
    assert [f.id for f in final["findings"]] == ids[:2]
    assert sink.saved[0]["rejected"], "phải lưu cả finding bị loại để đo chất lượng agent"


def test_scanner_bat_dung_lo_hong_da_cai(run_graph):
    _, _, state = run_graph(code_readable=["payment-api"])
    rules = {f.rule_id for f in state["findings"] if f.origin == "scanner"}
    assert "DL3002" in rules
    assert "K8S-SINGLE-REPLICA" in rules


# ── 5. Client OpenAI (không chạm mạng) ───────────────────────────────────────

def test_openai_client_parse_finding_va_ep_origin():
    payload = {"findings": [{
        "id": "X1", "axis": "security", "title": "root", "detail": "d",
        "service_key": "payment-api", "evidence_ids": ["e1"],
        "principle_ids": ["P-SEC-001"], "severity": 4, "confidence": 0.8,
        "tradeoff": None,
    }]}
    llm = OpenAILLM(model="test", client=StubOpenAI(payload))
    out = llm.analyze("security", {"axis": "security", "evidence": [], "principles": [],
                                   "graph_findings": []})
    assert out[0].origin == "llm", "origin phải do code đặt, không tin field từ model"
    assert out[0].blast_radius == 0, "model không được đặt blast_radius"
    assert llm.usage.calls == 1


def test_openai_client_gui_dung_strict_schema():
    llm = OpenAILLM(model="test", client=StubOpenAI({"findings": []}))
    llm.analyze("cost", {"axis": "cost", "evidence": [], "principles": [],
                         "graph_findings": []})
    fmt = llm.client.calls[0]["response_format"]
    assert fmt["type"] == "json_schema"
    assert fmt["json_schema"]["strict"] is True
    assert fmt["json_schema"]["schema"]["additionalProperties"] is False


def test_openai_client_coi_refusal_la_loi():
    """Structured Outputs có thêm một kiểu lỗi: model từ chối thay vì trả JSON."""
    llm = OpenAILLM(model="test", max_retries=0,
                    client=StubOpenAI({"findings": []}, refusal="không thể trả lời"))
    with pytest.raises(RuntimeError, match="thất bại"):
        llm.analyze("security", {"axis": "security", "evidence": [],
                                 "principles": [], "graph_findings": []})


def test_openai_plan_evidence_loc_service_ngoai_tree():
    payload = {"requests": [
        {"service_key": "payment-api", "path": "Dockerfile", "why": "a"},
        {"service_key": "service-la", "path": "Dockerfile", "why": "b"}]}
    llm = OpenAILLM(model="test", client=StubOpenAI(payload))
    out = llm.plan_evidence({"graph_findings": [], "principles": [],
                             "trees": {"payment-api": ["Dockerfile"]}, "already_have": []})
    assert [r["service_key"] for r in out] == ["payment-api"]


# ── 6. Benchmark ─────────────────────────────────────────────────────────────

def test_dataset_smoke_hop_le():
    """dataset.resolve tự kiểm tra id trùng và service_key không tồn tại."""
    from dataset import resolve
    ds = resolve({"name": "smoke", "path": str(ROOT / "tests/fixtures/smoke-system")})
    assert len(ds.defects) == 9
    for d in ds.defects:
        assert d.detectable_by in {"graph_rule", "scanner", "llm"}
        assert d.keywords_any, f"{d.id} thiếu từ khoá đối chiếu"


def test_dataset_bao_loi_khi_thieu_ground_truth(tmp_path):
    """Repo data không có .idp-review/expected.yaml phải fail rõ ràng."""
    from dataset import resolve
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "catalog.yaml").write_text("spec: {id: svc}")
    with pytest.raises(FileNotFoundError, match="expected.yaml"):
        resolve({"name": "x", "path": str(tmp_path)})


def test_dataset_bao_loi_khi_ground_truth_tro_sai_service(tmp_path):
    """Chốt chặn nhãn lệch data: ground truth trỏ tới service không tồn tại."""
    from dataset import resolve
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "catalog.yaml").write_text("spec: {id: svc}")
    (tmp_path / ".idp-review").mkdir()
    (tmp_path / ".idp-review" / "expected.yaml").write_text(
        "case: x\ndefects:\n  - id: A\n    axis: cost\n    service_key: khong-ton-tai\n"
        "    title: t\n    detectable_by: llm\n    keywords_any: [[a]]\n")
    with pytest.raises(ValueError, match="không tồn tại"):
        resolve({"name": "x", "path": str(tmp_path)})


def test_duong_co_so_tat_dinh_dat_muc_mong_doi():
    """Đường cơ sở không LLM trên dataset smoke. Số này tụt = tầng tất định hỏng."""
    out = subprocess.run(
        [sys.executable, "benchmark/run_eval.py", "--dataset", "smoke", "--no-llm",
         "--out", "runs/test-eval.json"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    assert out.returncode == 0, out.stderr
    data = json.loads((ROOT / "runs/test-eval.json").read_text(encoding="utf-8"))
    r = data["runs"][0]["breakdown"]
    assert r["graph_rule"]["recall"] == 1.0
    assert r["scanner"]["recall"] == 1.0
    assert r["llm"]["recall"] == 0.0, "NullLLM không được bắt gì"