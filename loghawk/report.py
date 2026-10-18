"""文本与 JSON 输出渲染。"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Dict, Sequence

from .models import Alert, DetectionConfig, Severity
from .parser import ParseResult

_SEVERITIES = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def severity_counts(alerts: Sequence[Alert]) -> Dict[str, int]:
    counts = Counter(alert.severity.name for alert in alerts)
    return {severity.name: counts.get(severity.name, 0) for severity in _SEVERITIES}


def _iso(value: datetime) -> str:
    return value.isoformat(sep="T", timespec="seconds")


def _display_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def render_text(
    alerts: Sequence[Alert],
    parse_result: ParseResult,
    config: DetectionConfig,
    source: str,
    version: str,
) -> str:
    counts = severity_counts(alerts)
    lines = [
        f"LogHawk {version} | SSH 认证日志威胁分析",
        f"输入: {source}",
        (
            f"解析: 共 {parse_result.total_lines} 行 / 认证事件 "
            f"{parse_result.event_count} 条 / 忽略 {parse_result.ignored_lines} 行"
        ),
        (
            f"配置: 失败阈值 {config.failed_threshold} 次，窗口 "
            f"{config.window_minutes} 分钟，成功回溯 "
            f"{config.success_lookback_minutes} 分钟，枚举阈值 "
            f"{config.enumeration_threshold} 个用户名"
        ),
        "-" * 72,
    ]

    if not alerts:
        lines.append("未发现达到当前规则的异常。")
        lines.append("提示：规则匹配结果不等于安全结论，请结合主机侧事件继续研判。")
    else:
        for index, alert in enumerate(alerts, start=1):
            lines.extend(
                [
                    f"[{alert.severity.name}] {alert.rule_id} {alert.title}",
                    f"  来源 IP  : {alert.source_ip}",
                    f"  关联账号 : {alert.username or '-'}",
                    (
                        f"  时间范围 : {_display_time(alert.first_seen)} ~ "
                        f"{_display_time(alert.last_seen)}"
                    ),
                    f"  摘要     : {alert.summary}",
                    "  证据:",
                ]
            )
            for evidence in alert.evidence:
                lines.append(f"    - {evidence}")
            lines.append(f"  建议     : {alert.recommendation}")
            if index != len(alerts):
                lines.append("")

    lines.append("-" * 72)
    summary = " | ".join(
        f"{severity.name} {counts[severity.name]}" for severity in _SEVERITIES
    )
    lines.append(f"汇总: {summary}")
    if alerts:
        lines.append(f"共 {len(alerts)} 条告警。")
    else:
        lines.append("共 0 条告警。")
    lines.append("免责声明: 仅用于授权范围内的日志审计与安全研究。")
    return "\n".join(lines)


def render_json(
    alerts: Sequence[Alert],
    parse_result: ParseResult,
    config: DetectionConfig,
    source: str,
    version: str,
    ensure_ascii: bool = False,
) -> str:
    payload = {
        "tool": {"name": "LogHawk", "version": version},
        "input": {
            "source": source,
            "total_lines": parse_result.total_lines,
            "auth_events": parse_result.event_count,
            "ignored_lines": parse_result.ignored_lines,
        },
        "config": {
            "failed_threshold": config.failed_threshold,
            "window_minutes": config.window_minutes,
            "success_lookback_minutes": config.success_lookback_minutes,
            "enumeration_threshold": config.enumeration_threshold,
        },
        "summary": {
            "total": len(alerts),
            "by_severity": severity_counts(alerts),
        },
        "alerts": [
            {
                "rule_id": alert.rule_id,
                "title": alert.title,
                "severity": alert.severity.name,
                "source_ip": alert.source_ip,
                "username": alert.username,
                "first_seen": _iso(alert.first_seen),
                "last_seen": _iso(alert.last_seen),
                "summary": alert.summary,
                "evidence": list(alert.evidence),
                "line_numbers": list(alert.line_numbers),
                "recommendation": alert.recommendation,
            }
            for alert in alerts
        ],
    }
    return json.dumps(payload, ensure_ascii=ensure_ascii, indent=2)
