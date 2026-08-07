"""Các node LangGraph cho luồng rà soát thiết kế kiến trúc.

Ba nguyên tắc chi phối:
  1. Node tất định PHÁT HIỆN, node LLM DIỄN GIẢI. Không đảo ngược.
  2. Quyền đọc chốt ở node đầu; mọi node sau lọc theo scope / code_readable.
  3. Finding không neo được thì bị LOẠI ở verify, không được sửa cho hợp lệ.
"""

from __future__ import annotations

import networkx as nx
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send, interrupt

from .deps import get_deps
from .state import AXES, Axis, Evidence, Finding, ReviewState

SYNC_PROTOCOLS = {"REST", "gRPC", "http", "HTTP"}
MAX_EVIDENCE_ITERATIONS = 3
MAX_EVIDENCE_TOKENS = 60_000
SHARED_RESOURCE_FANIN = 2


# ── Node tất định ────────────────────────────────────────────────────────────

def resolve_scope(state: ReviewState, config) -> dict:
    """Chốt phạm vi quyền từ chính token của người dùng.

    Hai mức quyền tách biệt — chỗ dễ sai nhất:
      scope         : thấy metadata catalog (cần để tính blast radius)
      code_readable : được đọc source (thường hẹp hơn nhiều)
    """
    repo = get_deps(config).repo
    token = state["actor_token"]
    scope = repo.accessible_projects(token)
    return {
        "scope": scope,
        "code_readable": [s for s in scope if repo.can_read_code(token, s)],
        "iteration": 0,
        "evidence_tokens": 0,
    }


def load_catalog(state: ReviewState, config) -> dict:
    repo = get_deps(config).repo
    ref = state["commit_sha"]
    catalog = {}
    for key in state["scope"]:
        doc = repo.read_catalog(key, ref)
        if doc:
            catalog[key] = doc
    return {"catalog": catalog}


def build_graph(state: ReviewState, config) -> dict:
    """Dựng đồ thị và chạy luật TẤT ĐỊNH. Không gọi LLM ở đây.

    Quy ước chiều cạnh: dependent -> dependency (khớp ngữ nghĩa catalog.yaml).
    Do đó blast radius của N là số component PHỤ THUỘC vào N, tức ancestors(N).
    """
    g = nx.DiGraph()
    findings: list[Finding] = []

    for key, doc in state["catalog"].items():
        spec = doc.get("spec", {}) or {}
        g.add_node(key, kind="component", service_type=spec.get("type", "other"))

        roles = {m.get("role") for m in (spec.get("owners", {}) or {}).get("members", [])}
        if "maintainer" not in roles:
            findings.append(_rule_finding(
                "ARCH-OWNER-001", key, "availability",
                "Không có owner nào giữ role maintainer nên alert on-call không có đích", 2))

        for dep in spec.get("topology", []) or []:
            ref = dep.get("ref", "")
            kind, _, rest = ref.partition(":")
            ns, _, name = rest.partition("/")
            if not name or kind == "system":
                continue
            target = f"{ns}.{name}" if kind == "resource" else name
            g.add_node(target, kind="resource" if kind == "resource" else "component")
            g.add_edge(key, target, protocol=dep.get("protocol"))

    undirected = g.to_undirected()
    if undirected.number_of_nodes() > 2:
        for node in nx.articulation_points(undirected):
            findings.append(_rule_finding(
                "ARCH-SPOF-001", node, "availability",
                "Articulation point trong đồ thị phụ thuộc — xoá đi làm đồ thị đứt", 4))

    sync = [(u, v) for u, v, d in g.edges(data=True) if d.get("protocol") in SYNC_PROTOCOLS]
    # simple_cycles trả về chu trình bắt đầu từ node tuỳ PYTHONHASHSEED. Phải xoay
    # về node nhỏ nhất, nếu không finding đổi service_key giữa các lần chạy và
    # mọi phép đo eval trở nên nhiễu.
    cycles = sorted(_canonical_cycle(c) for c in nx.simple_cycles(g.edge_subgraph(sync)))
    for cycle in cycles:
        findings.append(_rule_finding(
            "ARCH-CYCLE-001", cycle[0], "availability",
            f"Chu trình gọi đồng bộ: {' -> '.join(cycle)}", 4))

    for node, deg in sorted(g.in_degree()):
        if g.nodes[node].get("kind") == "resource" and deg >= SHARED_RESOURCE_FANIN:
            findings.append(_rule_finding(
                "ARCH-SHARED-DB-001", node, "scalability",
                f"{deg} component dùng chung resource này (shared database coupling)", 3))

    return {
        "graph_json": nx.node_link_data(g, edges="edges"),
        "blast_radius": {n: len(nx.ancestors(g, n)) for n in g.nodes},
        "raw_findings": findings,
    }


def retrieve_principles(state: ReviewState, config) -> dict:
    """Truy vấn theo rule_id đã phát hiện, không phải một câu hỏi chung chung."""
    rule_ids = sorted({f.rule_id for f in state["raw_findings"] if f.rule_id})
    return {"principles": get_deps(config).principles.search(rule_ids, list(AXES))}


def collect_evidence(state: ReviewState, config) -> dict:
    """Lấy đúng file được yêu cầu, rồi chạy scanner.

    Lọc theo code_readable TRƯỚC khi fetch. Đây là chốt chặn rò rỉ: kể cả khi
    LLM xin file ngoài phạm vi, request đó bị bỏ tại đây chứ không đi tiếp.
    """
    deps = get_deps(config)
    allowed = set(state["code_readable"])
    ref = state["commit_sha"]
    have = {(e.service_key, e.path) for e in state.get("evidence", [])}

    fetched, skipped = [], 0
    for req in state.get("evidence_requests", []):
        key, path = req.get("service_key"), req.get("path")
        if key not in allowed:
            skipped += 1
            continue
        if (key, path) in have:
            continue
        blob = deps.repo.read_file(key, path, ref)
        if blob:
            fetched.append(blob)

    evidence = [
        Evidence(
            id=f"ev-{b['service_key']}-{b['path']}",
            service_key=b["service_key"],
            path=b["path"],
            end_line=b["content"].count("\n") + 1,
            content=b["content"],
            blob_sha=b["blob_sha"],
        )
        for b in fetched
    ]

    scan_findings: list[Finding] = []
    for key in sorted({b["service_key"] for b in fetched}):
        files = [b for b in fetched if b["service_key"] == key]
        ev, fd = deps.scanner.scan(key, files)
        evidence.extend(ev)
        scan_findings.extend(fd)

    out: dict = {
        "evidence": evidence,
        "raw_findings": scan_findings,
        "iteration": state.get("iteration", 0) + 1,
        "evidence_tokens": state.get("evidence_tokens", 0)
        + sum(len(e.content) // 4 for e in evidence),
    }
    if skipped:
        out["errors"] = [f"{skipped} request bị bỏ vì ngoài phạm vi code_readable"]
    return out


def verify(state: ReviewState, config) -> dict:
    """Cổng chống bịa. Tất định, không gọi LLM.

    Finding origin='llm' phải qua ba phép kiểm tra, trượt một là loại — không sửa:
      1. evidence_ids không rỗng và đều tồn tại
      2. principle_ids đều nằm trong tập RAG đã truy hồi
      3. service_key nằm trong scope
    Finding graph_rule / scanner đã tất định nên chỉ kiểm tra (3).
    """
    evidence_ids = {e.id for e in state.get("evidence", [])}
    principle_ids = {p["id"] for p in state.get("principles", [])}
    scope = set(state["scope"])

    kept: list[Finding] = []
    rejected: list[Finding] = []
    for f in state["raw_findings"]:
        in_scope = f.service_key in scope or any(f.service_key.endswith(s) for s in scope)
        if f.origin == "llm":
            ok = (
                in_scope
                and bool(f.evidence_ids)
                and set(f.evidence_ids) <= evidence_ids
                and set(f.principle_ids) <= principle_ids
            )
        else:
            ok = True
        (kept if ok else rejected).append(f)

    return {"findings": kept, "rejected": rejected}


def score_and_rank(state: ReviewState, config) -> dict:
    """Xếp ưu tiên bằng số học. Cùng input → cùng thứ tự."""
    blast = state.get("blast_radius", {})
    for f in state["findings"]:
        f.blast_radius = blast.get(f.service_key, 0)
        f.priority = round(f.severity * (1 + f.blast_radius) * f.confidence, 4)
    return {"findings": sorted(state["findings"], key=lambda f: (-f.priority, f.id))}


def persist(state: ReviewState, config) -> dict:
    """Lưu cả `rejected` — đó là dữ liệu để đo chất lượng agent theo thời gian."""
    get_deps(config).sink.save(
        state["review_id"], state["findings"], state.get("rejected", []))
    return {"persisted": True}


# ── Node gọi LLM ─────────────────────────────────────────────────────────────

def plan_evidence(state: ReviewState, config) -> dict:
    """LLM quyết định cần đọc file nào — thay cho việc dump sẵn cả repo.

    Input gồm cây thư mục nhưng KHÔNG kèm nội dung file.
    """
    deps = get_deps(config)
    ref = state["commit_sha"]
    trees = {k: deps.repo.list_tree(k, ref) for k in state["code_readable"]}
    reqs = deps.llm.plan_evidence({
        "graph_findings": [f.model_dump() for f in state["raw_findings"]],
        "principles": state.get("principles", []),
        "trees": trees,
        "already_have": [[e.service_key, e.path] for e in state.get("evidence", [])],
    })
    return {"evidence_requests": reqs}


def analyze_axis(payload: dict, config) -> dict:
    """Một nhánh song song cho mỗi trục (gọi qua Send).

    Mỗi nhánh chỉ nhận subset nguyên tắc thuộc trục của nó. Hỏi cả bốn trục
    trong một prompt luôn cho ra bốn câu trả lời nông.
    """
    axis = payload["axis"]
    principles = [p for p in payload.get("principles", []) if p.get("axis") == axis]
    findings = get_deps(config).llm.analyze(axis, {
        "axis": axis,
        "evidence": [e.model_dump() for e in payload.get("evidence", [])],
        "principles": principles,
        "graph_findings": [f.model_dump() for f in payload.get("raw_findings", [])],
    })
    return {"raw_findings": [f for f in findings if f.axis == axis]}


def compose_report(state: ReviewState, config) -> dict:
    return {"report": get_deps(config).llm.compose(state["findings"])}


# ── HITL ─────────────────────────────────────────────────────────────────────

def human_review(state: ReviewState, config) -> dict:
    """Dừng graph chờ kiến trúc sư duyệt. Checkpointer giữ state qua nhiều ngày."""
    decision = interrupt({
        "review_id": state["review_id"],
        "findings": [f.model_dump() for f in state["findings"]],
        "action": "Duyệt / loại / sửa từng finding trước khi phát hành",
    })
    accepted = set(decision.get("accepted", []))
    return {"findings": [f for f in state["findings"] if f.id in accepted]}


# ── Điều hướng ───────────────────────────────────────────────────────────────

def route_after_scope(state: ReviewState) -> str:
    return "load_catalog" if state["scope"] else END


def route_after_evidence(state: ReviewState):
    """Ba chặn cùng lúc để vòng lặp không chạy vô hạn và không đốt token."""
    requested = {(r.get("service_key"), r.get("path"))
                 for r in state.get("evidence_requests", [])}
    collected = {(e.service_key, e.path) for e in state.get("evidence", [])}

    if (
        state.get("iteration", 0) < MAX_EVIDENCE_ITERATIONS
        and state.get("evidence_tokens", 0) < MAX_EVIDENCE_TOKENS
        and bool(requested - collected)      # còn file MỚI, không xin lại file cũ
    ):
        return "plan_evidence"

    return [Send("analyze_axis", {**state, "axis": axis}) for axis in AXES]


# ── Lắp graph ────────────────────────────────────────────────────────────────

def build_review_graph(checkpointer=None):
    b = StateGraph(ReviewState)
    for name, fn in [
        ("resolve_scope", resolve_scope),
        ("load_catalog", load_catalog),
        ("build_graph", build_graph),
        ("retrieve_principles", retrieve_principles),
        ("plan_evidence", plan_evidence),
        ("collect_evidence", collect_evidence),
        ("analyze_axis", analyze_axis),
        ("verify", verify),
        ("score_and_rank", score_and_rank),
        ("compose_report", compose_report),
        ("human_review", human_review),
        ("persist", persist),
    ]:
        b.add_node(name, fn)

    b.add_edge(START, "resolve_scope")
    b.add_conditional_edges("resolve_scope", route_after_scope, ["load_catalog", END])
    b.add_edge("load_catalog", "build_graph")
    b.add_edge("build_graph", "retrieve_principles")
    b.add_edge("retrieve_principles", "plan_evidence")
    b.add_edge("plan_evidence", "collect_evidence")
    b.add_conditional_edges("collect_evidence", route_after_evidence,
                            ["plan_evidence", "analyze_axis"])
    b.add_edge("analyze_axis", "verify")     # LangGraph tự gom các nhánh song song
    b.add_edge("verify", "score_and_rank")
    b.add_edge("score_and_rank", "compose_report")
    b.add_edge("compose_report", "human_review")
    b.add_edge("human_review", "persist")
    b.add_edge("persist", END)
    return b.compile(checkpointer=checkpointer)


def _rule_finding(rule_id: str, service_key: str, axis: Axis,
                  detail: str, severity: int) -> Finding:
    """Finding từ luật đồ thị — origin='graph_rule' nên verify không đòi evidence."""
    return Finding(
        id=f"{rule_id}:{service_key}", axis=axis, title=rule_id,
        service_key=service_key, detail=detail, origin="graph_rule",
        rule_id=rule_id, severity=severity, confidence=1.0,
    )


def _canonical_cycle(cycle: list[str]) -> tuple[str, ...]:
    """Xoay chu trình về node nhỏ nhất để định danh ổn định qua mọi lần chạy."""
    i = cycle.index(min(cycle))
    return tuple(cycle[i:] + cycle[:i])
