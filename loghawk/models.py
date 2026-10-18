"""LogHawk 的核心数据模型。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Optional, Tuple


class Severity(IntEnum):
    """告警级别。数值便于比较与排序。"""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            allowed = ", ".join(item.name for item in cls)
            raise ValueError(f"未知告警级别 {name!r}，可选值: {allowed}") from exc

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True)
class AuthEvent:
    """从单行 OpenSSH 日志中还原的一次认证事件。"""

    timestamp: datetime
    host: str
    pid: Optional[int]
    action: str  # "failed" 或 "accepted"
    username: str
    source_ip: str
    port: Optional[int]
    auth_method: str
    invalid_user: bool
    line_number: int
    raw: str


@dataclass(frozen=True)
class DetectionConfig:
    """检测阈值与时间窗口。所有时间窗口单位为分钟。"""

    failed_threshold: int = 5
    window_minutes: int = 5
    success_lookback_minutes: int = 10
    enumeration_threshold: int = 3

    def __post_init__(self) -> None:
        for field_name in (
            "failed_threshold",
            "window_minutes",
            "success_lookback_minutes",
            "enumeration_threshold",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{field_name} 必须是大于 0 的整数")


@dataclass(frozen=True)
class Alert:
    """一条可解释、可追溯的检测结果。"""

    rule_id: str
    title: str
    severity: Severity
    source_ip: str
    username: Optional[str]
    first_seen: datetime
    last_seen: datetime
    summary: str
    evidence: Tuple[str, ...]
    line_numbers: Tuple[int, ...]
    recommendation: str
