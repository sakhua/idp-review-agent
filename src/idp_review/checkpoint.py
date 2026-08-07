"""Helper tạo checkpointer với allowlist msgpack tường minh.

LangGraph mặc định cho phép deserialize mọi type nhưng kèm cảnh báo, và sẽ chặn
ở version sau. Khai báo tường minh các type của mình ngay từ đầu để không phải
sửa gấp khi nâng version.
"""

from __future__ import annotations

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

ALLOWED_MSGPACK_MODULES = (
    ("idp_review.state", "Finding"),
    ("idp_review.state", "Evidence"),
)


def make_serde() -> JsonPlusSerializer:
    return JsonPlusSerializer(allowed_msgpack_modules=ALLOWED_MSGPACK_MODULES)


def memory_checkpointer() -> InMemorySaver:
    """Dùng cho test và benchmark. Production dùng PostgresSaver(serde=make_serde())."""
    return InMemorySaver(serde=make_serde())
