"""Nạp bộ dữ liệu benchmark từ thư mục local hoặc từ một git repo.

Một "dataset" là bất kỳ thư mục nào có:
  - mỗi service một thư mục con, mỗi thư mục có catalog.yaml ở gốc
  - .idp-review/expected.yaml chứa ground truth

Ground truth nằm TRONG repo data chứ không phải repo engine. Lý do: nhãn mô tả
đúng một ảnh chụp của data. Để hai bên ở hai repo khác nhau thì sớm muộn chúng
lệch nhau và bạn đo sai mà không biết.

Về pin phiên bản: luôn ghi `ref` là commit SHA khi bắt đầu đo nghiêm túc. Trỏ vào
`main` nghĩa là data đổi dưới chân bạn và số recall tuần này không so được với
tuần trước.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

GROUND_TRUTH_REL = ".idp-review/expected.yaml"
CACHE_DIR = Path(".cache/datasets")


@dataclass
class Defect:
    id: str
    axis: str
    service_key: str
    title: str
    detectable_by: str
    keywords_any: list[list[str]]


@dataclass
class Dataset:
    name: str
    root: Path
    defects: list[Defect]
    source: str          # "local:<path>" hoặc "git:<url>@<ref>"
    commit: str | None   # SHA thật sau khi checkout, để ghi vào báo cáo

    @property
    def fingerprint(self) -> str:
        """Định danh phiên bản data để ghi kèm mỗi lần đo."""
        return self.commit[:12] if self.commit else "local-uncommitted"


def load_registry(path: str | Path = "datasets.yaml") -> dict[str, dict]:
    items = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    return {d["name"]: d for d in items}


def resolve(spec: dict, refresh: bool = False) -> Dataset:
    """Trả về Dataset từ một mục trong datasets.yaml."""
    name = spec["name"]
    if spec.get("path"):
        root = Path(spec["path"]).resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"dataset '{name}': không thấy {root}")
        return _build(name, root, f"local:{root}", _git_sha(root))

    url, ref = spec["url"], spec.get("ref", "HEAD")
    root = _clone_cached(url, ref, refresh=refresh)
    return _build(name, root, f"git:{url}@{ref}", _git_sha(root))


def resolve_url(url: str, ref: str = "HEAD", refresh: bool = False) -> Dataset:
    root = _clone_cached(url, ref, refresh=refresh)
    return _build(url.rsplit("/", 1)[-1], root, f"git:{url}@{ref}", _git_sha(root))


# ── nội bộ ───────────────────────────────────────────────────────────────────

def _build(name: str, root: Path, source: str, commit: str | None) -> Dataset:
    gt = root / GROUND_TRUTH_REL
    if not gt.is_file():
        raise FileNotFoundError(
            f"dataset '{name}': thiếu {GROUND_TRUTH_REL}. "
            "Ground truth phải nằm trong repo data, không phải repo engine.")
    spec = yaml.safe_load(gt.read_text(encoding="utf-8"))
    defects = [Defect(**d) for d in spec["defects"]]

    ids = [d.id for d in defects]
    if len(ids) != len(set(ids)):
        raise ValueError(f"dataset '{name}': id defect bị trùng")

    services = {p.parent.name for p in root.glob("*/catalog.yaml")}
    unknown = {d.service_key for d in defects} - services
    # service_key dạng "<ns>.<resource>" là tài nguyên hạ tầng, không có thư mục.
    unknown = {u for u in unknown if "." not in u}
    if unknown:
        raise ValueError(f"dataset '{name}': ground truth trỏ tới service không tồn tại: {unknown}")

    return Dataset(name=name, root=root, defects=defects, source=source, commit=commit)


def _clone_cached(url: str, ref: str, refresh: bool = False) -> Path:
    key = hashlib.sha1(f"{url}@{ref}".encode()).hexdigest()[:12]
    dest = CACHE_DIR / key
    if dest.is_dir() and not refresh:
        return dest
    if dest.is_dir():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    _run(["git", "clone", "--quiet", "--depth", "1", url, str(dest)])
    if ref not in ("HEAD", "", None):
        try:
            # Fetch nông đúng ref cần — chạy được cả với branch lẫn commit SHA.
            _run(["git", "-C", str(dest), "fetch", "--quiet", "--depth", "1", "origin", ref])
            _run(["git", "-C", str(dest), "checkout", "--quiet", "FETCH_HEAD"])
        except subprocess.CalledProcessError:
            # Server không cho fetch theo SHA -> lấy đủ lịch sử rồi checkout.
            _run(["git", "-C", str(dest), "fetch", "--quiet", "--unshallow"])
            _run(["git", "-C", str(dest), "checkout", "--quiet", ref])
    return dest


def _git_sha(root: Path) -> str | None:
    try:
        out = _run(["git", "-C", str(root), "rev-parse", "HEAD"])
        return out.strip()
    except Exception:      # noqa: BLE001 — thư mục không phải git repo
        return None


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
