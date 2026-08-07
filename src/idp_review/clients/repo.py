"""RepoClient đọc từ thư mục trên đĩa, hoặc clone từ một git URL.

Bố cục mong đợi: mỗi service là một thư mục con, có catalog.yaml ở gốc thư mục đó.

    <root>/
      payment-api/
        catalog.yaml
        Dockerfile
        k8s/deploy.yaml
      notify-worker/
        catalog.yaml
        ...

Về phân quyền: bản này lấy quyền từ tham số truyền vào (dùng cho benchmark).
Khi lên production, thay bằng GitLabRepoClient gọi API bằng chính token của
người dùng — lúc đó GitLab tự thực thi quyền và bạn không phải tự viết authz.
"""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path

import yaml

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "dist", "build"}
MAX_FILE_BYTES = 200_000


class LocalRepoClient:
    def __init__(self, root: str | Path,
                 scope: list[str] | None = None,
                 code_readable: list[str] | None = None):
        self.root = Path(root)
        discovered = sorted(p.parent.name for p in self.root.glob("*/catalog.yaml"))
        self.scope = scope if scope is not None else discovered
        self._code = set(code_readable if code_readable is not None else self.scope)

    # ── RepoClient ───────────────────────────────────────────────────────────

    def accessible_projects(self, token: str) -> list[str]:
        return list(self.scope)

    def can_read_code(self, token: str, service_key: str) -> bool:
        return service_key in self._code

    def read_catalog(self, service_key: str, ref: str) -> dict | None:
        path = self.root / service_key / "catalog.yaml"
        if not path.is_file():
            return None
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def list_tree(self, service_key: str, ref: str) -> list[str]:
        base = self.root / service_key
        if not base.is_dir():
            return []
        out = []
        for p in sorted(base.rglob("*")):
            if p.is_file() and not any(part in SKIP_DIRS for part in p.parts):
                out.append(str(p.relative_to(base)))
        return out

    def read_file(self, service_key: str, path: str, ref: str) -> dict | None:
        target = (self.root / service_key / path).resolve()
        base = (self.root / service_key).resolve()
        # Chặn path traversal: LLM có thể sinh ra "../../etc/passwd".
        if base not in target.parents and target != base:
            return None
        if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
            return None
        content = target.read_text(encoding="utf-8", errors="replace")
        return {
            "service_key": service_key,
            "path": path,
            "content": content,
            "blob_sha": hashlib.sha1(content.encode()).hexdigest()[:12],
        }


def clone_repo(url: str, ref: str = "HEAD", depth: int = 1) -> Path:
    """Clone nông một repo về thư mục tạm và trả về đường dẫn.

    Dùng để test thực tế bằng link thay vì thư mục local:
        client = LocalRepoClient(clone_repo("https://github.com/ban/repo.git"))
    """
    dest = Path(tempfile.mkdtemp(prefix="idp-review-"))
    cmd = ["git", "clone", "--depth", str(depth), url, str(dest)]
    subprocess.run(cmd, check=True, capture_output=True)
    if ref != "HEAD":
        subprocess.run(["git", "-C", str(dest), "checkout", ref],
                       check=True, capture_output=True)
    return dest
