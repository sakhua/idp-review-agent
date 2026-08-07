"""Chạy benchmark và báo cáo recall.

    python benchmark/run_eval.py --dataset smoke --no-llm       # CI, offline
    python benchmark/run_eval.py --dataset payment-system       # clone từ GitHub
    python benchmark/run_eval.py --dataset payment-system --runs 3
    python benchmark/run_eval.py --url https://github.com/u/repo.git --ref <sha>

Vì LLM không tất định, một lần chạy KHÔNG phải là kết quả. Chạy tối thiểu 3 lần
và báo cáo khoảng dao động; nếu khoảng đó rộng hơn mức cải thiện bạn đang đo thì
bạn chưa đo được gì.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

from langgraph.types import Command

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dataset import Dataset, load_registry, resolve, resolve_url   # noqa: E402
from idp_review.checkpoint import memory_checkpointer              # noqa: E402
from idp_review.clients.principles import FilePrincipleStore       # noqa: E402
from idp_review.clients.repo import LocalRepoClient                # noqa: E402
from idp_review.clients.scanner import RegexScanner                # noqa: E402
from idp_review.clients.sink import MemorySink                     # noqa: E402
from idp_review.deps import Deps                                   # noqa: E402
from idp_review.graph import build_review_graph                    # noqa: E402
from idp_review.state import Finding                               # noqa: E402
from matcher import breakdown, by_axis, match                      # noqa: E402


class NullLLM:
    """Dùng với --no-llm để đo riêng tầng tất định làm đường cơ sở.

    Vẫn xin file theo heuristic cố định để scanner có gì mà quét.
    """

    WANTED = ("Dockerfile", "k8s/", "config/", ".yaml", ".yml")

    def plan_evidence(self, ctx):
        return [{"service_key": k, "path": p, "why": "baseline"}
                for k, tree in sorted(ctx["trees"].items()) for p in tree
                if any(w in p for w in self.WANTED) and "catalog.yaml" not in p][:12]

    def analyze(self, axis, ctx):
        return []

    def compose(self, findings):
        return {"summary": "baseline", "top_risks": []}


def run_once(root: Path, llm, review_id: str) -> tuple[list[Finding], list[Finding], dict]:
    sink = MemorySink()
    graph = build_review_graph(checkpointer=memory_checkpointer())
    config = {"configurable": {
        "thread_id": review_id,
        "deps": Deps(repo=LocalRepoClient(root), llm=llm,
                     principles=FilePrincipleStore(ROOT / "principles" / "principles.yaml"),
                     scanner=RegexScanner(), sink=sink),
    }}
    state = graph.invoke(
        {"review_id": review_id, "commit_sha": "HEAD", "actor_token": "eval"}, config)

    # Eval tự duyệt hết ở bước HITL để đi qua đúng đường chạy thật.
    ids = [f["id"] for f in state["__interrupt__"][0].value["findings"]]
    final = graph.invoke(Command(resume={"accepted": ids}), config)
    return final["findings"], final.get("rejected", []), final.get("report") or {}


def evaluate(ds: Dataset, llm, runs: int) -> list[dict]:
    out = []
    for i in range(runs):
        findings, rejected, _ = run_once(ds.root, llm, f"{ds.name}-{i}")
        res = match(ds.defects, findings)
        llm_total = len([f for f in findings if f.origin == "llm"]) + len(rejected)
        out.append({
            "recall": res.recall,
            "breakdown": breakdown(ds.defects, res),
            "axis": by_axis(ds.defects, res),
            "unmatched": len(res.unmatched),
            "unmatched_titles": [f.title for f in res.unmatched],
            "hallucination_rate": (len(rejected) / llm_total) if llm_total else None,
        })
    return out


def report(ds: Dataset, runs: list[dict]) -> dict:
    bar = "=" * 64
    print(f"\n{bar}\nDATASET  : {ds.name}   ({len(runs)} lần chạy)")
    print(f"NGUỒN    : {ds.source}")
    print(f"PHIÊN BẢN: {ds.fingerprint}   ← ghi số này lại khi so sánh giữa các lần đo")
    print(bar)

    overall = [r["recall"] for r in runs]
    spread = f"   (dao động {min(overall):.0%}–{max(overall):.0%})" if len(runs) > 1 else ""
    print(f"\nRecall tổng      : {statistics.mean(overall):.0%}{spread}")
    print("  Con số này bị tầng tất định kéo lên. Xem dòng llm bên dưới.\n")

    print(f"{'Cơ chế':<12}{'Bắt/Tổng':>10}{'Recall':>10}   Bỏ sót")
    print("-" * 64)
    for mech in ("graph_rule", "scanner", "llm"):
        vals = [r["breakdown"][mech] for r in runs]
        total = vals[0]["total"]
        if not total:
            continue
        hits = [v["hit"] for v in vals]
        missed = sorted({m for v in vals for m in v["missed"]})
        print(f"{mech:<12}{f'{statistics.mean(hits):.1f}/{total}':>10}"
              f"{statistics.mean(hits) / total:>9.0%}   {', '.join(missed) or '—'}")

    print(f"\n{'Trục':<14}{'Recall':>10}")
    print("-" * 64)
    for axis in ("security", "availability", "scalability", "cost"):
        vals = [r["axis"][axis]["recall"] for r in runs
                if r["axis"][axis]["recall"] is not None]
        if vals:
            print(f"{axis:<14}{statistics.mean(vals):>9.0%}")

    hall = [r["hallucination_rate"] for r in runs if r["hallucination_rate"] is not None]
    if hall:
        print(f"\nTỉ lệ bịa (bị verify loại) : {statistics.mean(hall):.0%}")
    print(f"Finding ngoài ground truth : "
          f"{statistics.mean([r['unmatched'] for r in runs]):.1f} "
          "(không hẳn là sai — có thể là lỗi thật chưa gán nhãn)")
    for t in sorted({t for r in runs for t in r["unmatched_titles"]})[:5]:
        print(f"    · {t}")

    return {
        "dataset": ds.name, "source": ds.source, "dataset_commit": ds.commit,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runs": runs,
        "recall_mean": statistics.mean(overall),
        "llm_recall_mean": statistics.mean(
            [r["breakdown"]["llm"]["recall"] or 0 for r in runs]),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="smoke", help="tên trong datasets.yaml")
    ap.add_argument("--url", default=None, help="git URL, bỏ qua datasets.yaml")
    ap.add_argument("--ref", default="HEAD", help="branch hoặc commit SHA khi dùng --url")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--no-llm", action="store_true", help="chỉ đo tầng tất định")
    ap.add_argument("--refresh", action="store_true", help="clone lại, bỏ cache")
    ap.add_argument("--out", default="runs/eval.json")
    args = ap.parse_args()

    if args.url:
        ds = resolve_url(args.url, args.ref, refresh=args.refresh)
    else:
        registry = load_registry(ROOT / "datasets.yaml")
        if args.dataset not in registry:
            sys.exit(f"Không có dataset '{args.dataset}'. Có: {', '.join(registry)}")
        ds = resolve(registry[args.dataset], refresh=args.refresh)

    if args.no_llm:
        llm = NullLLM()
    else:
        from idp_review.clients.openai_llm import OpenAILLM
        llm = OpenAILLM()
        print(f"Model: {llm.model}")

    result = report(ds, evaluate(ds, llm, args.runs))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nĐã lưu {out}")


if __name__ == "__main__":
    main()
