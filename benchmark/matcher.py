"""Đối chiếu finding do agent sinh ra với ground truth.

Quyết định thiết kế: matcher TẤT ĐỊNH (khớp axis + service_key + từ khoá), không
dùng LLM-as-judge. Lý do: nếu thước đo cũng là LLM thì bạn không phân biệt được
"model tốt lên" với "judge dễ tính hơn". Đổi lại, từ khoá phải chọn kỹ — ưu tiên
token kỹ thuật (timeout, privileged, latest, root) vì chúng giữ nguyên khi model
viết tiếng Việt.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dataset import Defect
from idp_review.state import Finding


@dataclass
class MatchResult:
    hit: dict[str, Finding] = field(default_factory=dict)     # defect_id -> finding
    missed: list[Defect] = field(default_factory=list)
    unmatched: list[Finding] = field(default_factory=list)

    @property
    def recall(self) -> float:
        total = len(self.hit) + len(self.missed)
        return len(self.hit) / total if total else 0.0


def _matches(defect: Defect, finding: Finding) -> bool:
    if finding.axis != defect.axis:
        return False
    if finding.service_key != defect.service_key:
        return False
    hay = finding.haystack()
    return any(all(kw.lower() in hay for kw in group) for group in defect.keywords_any)


def match(defects: list[Defect], findings: list[Finding]) -> MatchResult:
    """Mỗi finding chỉ được tính cho tối đa một defect, và ngược lại."""
    res = MatchResult()
    used: set[int] = set()

    for d in defects:
        for i, f in enumerate(findings):
            if i in used or not _matches(d, f):
                continue
            res.hit[d.id] = f
            used.add(i)
            break
        else:
            res.missed.append(d)

    res.unmatched = [f for i, f in enumerate(findings) if i not in used]
    return res


def breakdown(defects: list[Defect], res: MatchResult) -> dict[str, dict]:
    """Tách recall theo cơ chế phát hiện.

    Đây là bảng quan trọng nhất của cả bộ eval: recall tổng bị scanner kéo lên,
    và con số nói về CHẤT LƯỢNG MODEL chỉ nằm ở dòng llm.
    """
    out: dict[str, dict] = {}
    for mech in ("graph_rule", "scanner", "llm"):
        group = [d for d in defects if d.detectable_by == mech]
        got = [d for d in group if d.id in res.hit]
        out[mech] = {
            "total": len(group),
            "hit": len(got),
            "recall": len(got) / len(group) if group else None,
            "missed": [d.id for d in group if d.id not in res.hit],
        }
    return out


def by_axis(defects: list[Defect], res: MatchResult) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for axis in ("security", "availability", "scalability", "cost"):
        group = [d for d in defects if d.axis == axis]
        got = [d for d in group if d.id in res.hit]
        out[axis] = {"total": len(group), "hit": len(got),
                     "recall": len(got) / len(group) if group else None}
    return out
