"""LogHawk 命令行入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence, TextIO

from . import __version__
from .detector import detect
from .models import Alert, DetectionConfig, Severity
from .parser import ParseResult, parse_file, parse_lines
from .report import render_json, render_text

_EPILOG = """用法:
  python -m loghawk demo/auth.log
  python -m loghawk demo/auth.log --format json --min-severity MEDIUM
  python -m loghawk demo/auth.log --fail-on CRITICAL
  cat /var/log/auth.log | python -m loghawk -

退出码:
  0  未发现达到 --fail-on 级别的告警
  1  发现达到 --fail-on 级别的告警
  2  参数、文件读取或解析过程出错
"""


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("必须是整数") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("必须大于 0")
    return value


def _year(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("年份必须是整数") from exc
    if not 1970 <= value <= 2100:
        raise argparse.ArgumentTypeError("年份必须在 1970 到 2100 之间")
    return value


def build_parser() -> argparse.ArgumentParser:
    severity_names = [severity.name for severity in Severity]
    parser = argparse.ArgumentParser(
        prog="loghawk",
        description="离线分析 OpenSSH 认证日志，检测暴力破解、异常成功登录与用户名枚举。",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="-",
        help="auth.log 路径（支持 .gz），使用 - 或省略时从标准输入读取",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="输出格式，默认 text",
    )
    parser.add_argument(
        "--failed-threshold",
        type=_positive_int,
        default=5,
        metavar="N",
        help="同一 IP 在时间窗内触发暴力破解的最少失败次数，默认 5",
    )
    parser.add_argument(
        "--window",
        type=_positive_int,
        default=5,
        metavar="MIN",
        help="暴力破解与用户名枚举的滑动窗口（分钟），默认 5",
    )
    parser.add_argument(
        "--success-lookback",
        type=_positive_int,
        default=10,
        metavar="MIN",
        help="成功登录向前回溯失败记录的时间（分钟），默认 10",
    )
    parser.add_argument(
        "--enum-threshold",
        type=_positive_int,
        default=3,
        metavar="N",
        help="触发用户名枚举的最少不同无效用户名数量，默认 3",
    )
    parser.add_argument(
        "--min-severity",
        choices=severity_names,
        default="LOW",
        help="仅输出不低于该级别的告警，默认 LOW",
    )
    parser.add_argument(
        "--fail-on",
        choices=("never",) + tuple(severity_names),
        default="HIGH",
        help="达到该级别时以退出码 1 结束，默认 HIGH；never 表示从不失败",
    )
    parser.add_argument(
        "--year",
        type=_year,
        default=None,
        help="syslog 时间戳缺失的年份，默认当前年份",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _read_input(path: str, year: Optional[int]) -> tuple[ParseResult, str]:
    if path == "-":
        return parse_lines(sys.stdin, default_year=year), "<stdin>"
    input_path = Path(path)
    return parse_file(input_path, default_year=year), str(input_path)


def _stream_encoding(stream: TextIO) -> str:
    return getattr(stream, "encoding", None) or "utf-8"


def _can_encode(text: str, encoding: str) -> bool:
    try:
        text.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def _write_text(stream: TextIO, text: str) -> None:
    """写入文本；编码不支持时降级为可显示的替换字符。"""

    payload = text + "\n"
    try:
        stream.write(payload)
    except UnicodeEncodeError:
        encoding = _stream_encoding(stream)
        try:
            payload = payload.encode(encoding, errors="replace").decode(encoding)
        except LookupError:
            payload = payload.encode("utf-8", errors="replace").decode("utf-8")
        stream.write(payload)


def _configure_standard_streams() -> None:
    """避免 argparse/错误信息在非 UTF-8 终端触发编码异常。"""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(
    argv: Optional[Sequence[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output = stdout or sys.stdout
    errors = stderr or sys.stderr

    try:
        parse_result, source = _read_input(args.path, args.year)
    except (OSError, EOFError) as exc:
        _write_text(errors, f"错误: 无法读取输入日志: {exc}")
        return 2

    try:
        config = DetectionConfig(
            failed_threshold=args.failed_threshold,
            window_minutes=args.window,
            success_lookback_minutes=args.success_lookback,
            enumeration_threshold=args.enum_threshold,
        )
    except ValueError as exc:
        _write_text(errors, f"错误: 检测参数无效: {exc}")
        return 2

    if parse_result.total_lines > 0 and parse_result.event_count == 0:
        _write_text(
            errors,
            "警告: 未识别到 SSH 认证事件，请确认日志为 OpenSSH syslog 格式。",
        )

    all_alerts = detect(parse_result.events, config)
    minimum = Severity[args.min_severity]
    visible_alerts: List[Alert] = [
        alert for alert in all_alerts if alert.severity >= minimum
    ]

    output_encoding = _stream_encoding(output)
    if args.format == "json":
        rendered = render_json(
            visible_alerts,
            parse_result,
            config,
            source,
            __version__,
            ensure_ascii=not _can_encode("中文", output_encoding),
        )
    else:
        rendered = render_text(
            visible_alerts, parse_result, config, source, __version__
        )
    _write_text(output, rendered)

    if args.fail_on == "never":
        return 0
    fail_level = Severity[args.fail_on]
    return 1 if any(alert.severity >= fail_level for alert in all_alerts) else 0


def entrypoint() -> None:
    _configure_standard_streams()
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # 允许 `loghawk ... | head` 一类管道提前关闭而不打印回溯。
        raise SystemExit(0) from None
