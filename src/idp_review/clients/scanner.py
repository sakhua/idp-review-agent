"""Scanner tất định, thuần Python, không cần cài binary ngoài.

Đây là bản tối giản để benchmark chạy được ở mọi máy. Lên production nên thay
bằng ProcessScanner gọi semgrep / trivy / hadolint / kube-score — cùng interface,
chỉ khác cách sinh Finding.

Mỗi luật có rule_id cố định và neo về đúng số dòng, nên không bao giờ bịa.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..state import Axis, Evidence, Finding


@dataclass(frozen=True)
class Rule:
    id: str
    axis: Axis
    title: str
    severity: int
    path_re: str
    line_re: str
    principle_id: str


RULES: tuple[Rule, ...] = (
    Rule("DL3002", "security", "Container chạy bằng root", 4,
         r"Dockerfile$", r"^\s*USER\s+root\b", "P-SEC-001"),
    Rule("SEC-HARDCODED-SECRET", "security", "Secret hardcode trong file", 5,
         r"\.(ya?ml|env|py|js|ts|json|properties)$",
         r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{8,}",
         "P-SEC-002"),
    Rule("K8S-SINGLE-REPLICA", "availability", "Chỉ có một replica", 3,
         r"\.ya?ml$", r"^\s*replicas:\s*1\s*$", "P-AVL-003"),
    Rule("IMG-LATEST-TAG", "cost", "Dùng image tag latest", 2,
         r"(Dockerfile|\.ya?ml)$", r"(?i)image:\s*\S+:latest\b", "P-CST-002"),
)

# Luật dạng "thiếu thứ gì đó" — không khớp regex mà là vắng mặt regex.
ABSENCE_RULES = (
    ("K8S-NO-PROBE", "availability", "Thiếu readiness/liveness probe", 3,
     r"k8s/.*\.ya?ml$", r"(readiness|liveness)Probe", "P-AVL-002"),
    ("K8S-NO-RESOURCES", "cost", "Thiếu resources.requests/limits", 3,
     r"k8s/.*\.ya?ml$", r"resources:", "P-CST-001"),
)


class RegexScanner:
    def scan(self, service_key: str,
             files: list[dict]) -> tuple[list[Evidence], list[Finding]]:
        evidence: list[Evidence] = []
        findings: list[Finding] = []

        for f in files:
            path, content = f["path"], f["content"]
            lines = content.splitlines()

            for rule in RULES:
                if not re.search(rule.path_re, path):
                    continue
                for i, line in enumerate(lines, start=1):
                    if re.search(rule.line_re, line):
                        ev_id = f"scan-{service_key}-{rule.id}-{path}-{i}"
                        evidence.append(Evidence(
                            id=ev_id, service_key=service_key, path=path,
                            start_line=i, end_line=i, content=line.strip(),
                            blob_sha=f["blob_sha"], source="scanner"))
                        findings.append(Finding(
                            id=f"{rule.id}:{service_key}:{path}:{i}",
                            axis=rule.axis, title=rule.title, service_key=service_key,
                            detail=f"{path}:{i} — {line.strip()}",
                            evidence_ids=[ev_id], principle_ids=[rule.principle_id],
                            origin="scanner", rule_id=rule.id,
                            severity=rule.severity, confidence=1.0))
                        break   # một finding mỗi luật mỗi file là đủ

            for rid, axis, title, severity, path_re, need_re, pid in ABSENCE_RULES:
                if re.search(path_re, path) and not re.search(need_re, content):
                    ev_id = f"scan-{service_key}-{rid}-{path}"
                    evidence.append(Evidence(
                        id=ev_id, service_key=service_key, path=path,
                        start_line=1, end_line=len(lines) or 1,
                        content=f"(không tìm thấy {need_re} trong {path})",
                        blob_sha=f["blob_sha"], source="scanner"))
                    findings.append(Finding(
                        id=f"{rid}:{service_key}:{path}", axis=axis, title=title,
                        service_key=service_key, detail=f"{path} thiếu cấu hình bắt buộc",
                        evidence_ids=[ev_id], principle_ids=[pid],
                        origin="scanner", rule_id=rid,
                        severity=severity, confidence=1.0))

        return evidence, findings
