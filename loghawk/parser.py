"""OpenSSH syslog 文本解析器。

只接受形如以下格式的日志行（Debian/Ubuntu/RHEL 的 /var/log/auth.log、
journalctl -o short 输出等）：

    Oct 18 09:12:05 web01 sshd[1201]: Accepted password for alice \
        from 203.0.113.24 port 51422 ssh2

解析器只读取日志，不执行任何系统命令或网络请求。
"""

from __future__ import annotations

import gzip
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .models import AuthEvent

_MONTHS = {
    "JAN": 1,
    "FEB": 2,
    "MAR": 3,
    "APR": 4,
    "MAY": 5,
    "JUN": 6,
    "JUL": 7,
    "AUG": 8,
    "SEP": 9,
    "OCT": 10,
    "NOV": 11,
    "DEC": 12,
}

# Oct 18 09:12:05 web01 sshd[1201]: ...
_SYSLOG_RE = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:-session)?(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

_FAILED_RE = re.compile(
    r"^Failed\s+(?P<method>\S+)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    r"(?:\s+ssh2)?(?::.*)?$"
)

_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    r"(?:\s+ssh2)?(?::.*)?$"
)


@dataclass(frozen=True)
class ParseResult:
    """一次解析的统计信息与事件集合。"""

    events: Tuple[AuthEvent, ...]
    total_lines: int
    ignored_lines: int

    @property
    def event_count(self) -> int:
        return len(self.events)


def _parse_timestamp(stamp: str, default_year: int) -> Optional[datetime]:
    parts = stamp.split()
    if len(parts) != 3:
        return None
    month = _MONTHS.get(parts[0].upper())
    if month is None:
        return None
    try:
        day = int(parts[1])
        hour, minute, second = (int(part) for part in parts[2].split(":"))
        return datetime(default_year, month, day, hour, minute, second)
    except (TypeError, ValueError):
        return None


def _parse_line(
    line: str, line_number: int, default_year: int
) -> Optional[AuthEvent]:
    match = _SYSLOG_RE.match(line.rstrip("\r\n"))
    if not match:
        return None

    timestamp = _parse_timestamp(match.group("stamp"), default_year)
    if timestamp is None:
        return None

    message = match.group("message")
    failed = _FAILED_RE.match(message)
    accepted = _ACCEPTED_RE.match(message)
    if not failed and not accepted:
        return None

    if failed:
        action = "failed"
        username = failed.group("user")
        source_ip = failed.group("ip")
        port_text = failed.group("port")
        auth_method = failed.group("method")
        invalid_user = failed.group("invalid") is not None
    else:
        assert accepted is not None
        action = "accepted"
        username = accepted.group("user")
        source_ip = accepted.group("ip")
        port_text = accepted.group("port")
        auth_method = accepted.group("method")
        invalid_user = False

    try:
        ipaddress.ip_address(source_ip)
        port = int(port_text)
    except ValueError:
        return None

    pid_text = match.group("pid")
    pid = int(pid_text) if pid_text else None
    return AuthEvent(
        timestamp=timestamp,
        host=match.group("host"),
        pid=pid,
        action=action,
        username=username,
        source_ip=source_ip,
        port=port,
        auth_method=auth_method,
        invalid_user=invalid_user,
        line_number=line_number,
        raw=line.rstrip("\r\n"),
    )


def parse_lines(
    lines: Iterable[str], default_year: Optional[int] = None
) -> ParseResult:
    """解析任意可迭代的日志行。

    时间戳不带年份，因此默认使用当前年份；处理历史日志时应显式传入
    ``default_year``。返回的事件按时间与行号稳定排序。
    """

    year = default_year if default_year is not None else datetime.now().year
    events: List[AuthEvent] = []
    total = 0

    for total, raw_line in enumerate(lines, start=1):
        event = _parse_line(raw_line, total, year)
        if event is not None:
            events.append(event)

    events.sort(key=lambda item: (item.timestamp, item.line_number))
    return ParseResult(
        events=tuple(events),
        total_lines=total,
        ignored_lines=total - len(events),
    )


def parse_file(path: Path, default_year: Optional[int] = None) -> ParseResult:
    """解析普通文本或 ``.gz`` 压缩日志文件。"""

    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            return parse_lines(handle, default_year=default_year)

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle, default_year=default_year)
