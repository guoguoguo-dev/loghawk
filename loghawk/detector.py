"""基于时间窗口的 SSH 认证威胁检测规则。

设计原则：
- 纯函数式检测，不读取环境、不访问网络；
- 每条告警都携带来源 IP、时间范围、行号和可解释证据；
- 规则宁少勿滥，默认阈值面向中小型主机日志。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Sequence, Tuple

from .models import Alert, AuthEvent, DetectionConfig, Severity

RULE_BRUTE_FORCE = "LH-001"
RULE_SUCCESS_AFTER_FAILURE = "LH-002"
RULE_USER_ENUMERATION = "LH-003"

_MAX_EVIDENCE_LINES = 12


def _format_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _format_line_numbers(events: Sequence[AuthEvent], limit: int = _MAX_EVIDENCE_LINES) -> str:
    numbers = [str(event.line_number) for event in events[:limit]]
    if len(events) > limit:
        numbers.append(f"...（共 {len(events)} 行）")
    return ", ".join(numbers)


def _usernames(events: Sequence[AuthEvent], limit: int = 5) -> str:
    counts = Counter(event.username for event in events)
    rendered = [f"{name}({count})" for name, count in counts.most_common(limit)]
    if len(counts) > limit:
        rendered.append(f"...（共 {len(counts)} 个账号）")
    return ", ".join(rendered)


def _detect_brute_force(
    events: Sequence[AuthEvent], config: DetectionConfig
) -> List[Alert]:
    failures_by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.action == "failed":
            failures_by_ip[event.source_ip].append(event)

    alerts: List[Alert] = []
    for source_ip in sorted(failures_by_ip):
        failures = failures_by_ip[source_ip]
        index = 0
        while index < len(failures):
            window = timedelta(minutes=config.window_minutes)
            limit = failures[index].timestamp + window
            end = index
            while end < len(failures) and failures[end].timestamp <= limit:
                end += 1
            group = failures[index:end]

            if len(group) >= config.failed_threshold:
                counts = Counter(event.username for event in group)
                main_target = counts.most_common(1)[0][0]
                alerts.append(
                    Alert(
                        rule_id=RULE_BRUTE_FORCE,
                        title="SSH 暴力破解尝试",
                        severity=Severity.HIGH,
                        source_ip=source_ip,
                        username=main_target,
                        first_seen=group[0].timestamp,
                        last_seen=group[-1].timestamp,
                        summary=(
                            f"{config.window_minutes} 分钟内来自 {source_ip} 的失败认证"
                            f"达到 {len(group)} 次（阈值 {config.failed_threshold}），"
                            f"主要目标账号为 {main_target}。"
                        ),
                        evidence=(
                            f"目标账号分布: {_usernames(group)}",
                            f"时间范围: {_format_time(group[0].timestamp)} ~ "
                            f"{_format_time(group[-1].timestamp)}",
                            f"日志行号: {_format_line_numbers(group)}",
                        ),
                        line_numbers=tuple(event.line_number for event in group),
                        recommendation=(
                            "确认该 IP 是否为授权扫描来源；如非授权，建议在边界设备"
                            "临时封禁、检查 SSH 暴露面，并启用密钥登录或登录限速。"
                        ),
                    )
                )
                index = end
            else:
                index += 1

    return alerts


def _detect_user_enumeration(
    events: Sequence[AuthEvent], config: DetectionConfig
) -> List[Alert]:
    invalid_by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.action == "failed" and event.invalid_user:
            invalid_by_ip[event.source_ip].append(event)

    alerts: List[Alert] = []
    for source_ip in sorted(invalid_by_ip):
        failures = invalid_by_ip[source_ip]
        index = 0
        while index < len(failures):
            limit = failures[index].timestamp + timedelta(
                minutes=config.window_minutes
            )
            end = index
            names = set()
            while end < len(failures) and failures[end].timestamp <= limit:
                names.add(failures[end].username)
                end += 1
            group = failures[index:end]

            if len(names) >= config.enumeration_threshold:
                ordered_names = sorted(names)
                rendered = ", ".join(ordered_names[:8])
                if len(ordered_names) > 8:
                    rendered += f" ...（共 {len(ordered_names)} 个）"
                alerts.append(
                    Alert(
                        rule_id=RULE_USER_ENUMERATION,
                        title="疑似 SSH 用户名枚举",
                        severity=Severity.MEDIUM,
                        source_ip=source_ip,
                        username=None,
                        first_seen=group[0].timestamp,
                        last_seen=group[-1].timestamp,
                        summary=(
                            f"{config.window_minutes} 分钟内来自 {source_ip} 的无效用户"
                            f"名称达到 {len(names)} 个（阈值 "
                            f"{config.enumeration_threshold}），疑似在探测有效账号。"
                        ),
                        evidence=(
                            f"无效用户名: {rendered}",
                            f"时间范围: {_format_time(group[0].timestamp)} ~ "
                            f"{_format_time(group[-1].timestamp)}",
                            f"日志行号: {_format_line_numbers(group)}",
                        ),
                        line_numbers=tuple(event.line_number for event in group),
                        recommendation=(
                            "审查该来源 IP 的访问意图；禁用 SSH 密码猜测面、限制"
                            "来源网段，并确认日志中不存在随后成功登录同一来源。"
                        ),
                    )
                )
                index = end
            else:
                index += 1

    return alerts


def _detect_success_after_failure(
    events: Sequence[AuthEvent], config: DetectionConfig
) -> List[Alert]:
    failures_by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
    accepted_by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.action == "failed":
            failures_by_ip[event.source_ip].append(event)
        else:
            accepted_by_ip[event.source_ip].append(event)

    lookback = timedelta(minutes=config.success_lookback_minutes)
    alerts: List[Alert] = []
    for source_ip in sorted(accepted_by_ip):
        failures = failures_by_ip.get(source_ip, [])
        last_alert_at: Dict[str, datetime] = {}
        for accepted in accepted_by_ip[source_ip]:
            previous = last_alert_at.get(accepted.username)
            if previous is not None and accepted.timestamp - previous <= lookback:
                continue

            window_start = accepted.timestamp - lookback
            prior = [
                event
                for event in failures
                if window_start <= event.timestamp < accepted.timestamp
            ]
            if len(prior) < config.failed_threshold:
                continue

            alerts.append(
                Alert(
                    rule_id=RULE_SUCCESS_AFTER_FAILURE,
                    title="暴力破解后登录成功",
                    severity=Severity.CRITICAL,
                    source_ip=source_ip,
                    username=accepted.username,
                    first_seen=prior[0].timestamp,
                    last_seen=accepted.timestamp,
                    summary=(
                        f"来源 IP 在成功登录前 {config.success_lookback_minutes} 分钟内"
                        f"有 {len(prior)} 次失败认证，随后账号 {accepted.username} 通过"
                        f" {accepted.auth_method} 登录成功。"
                    ),
                    evidence=(
                        f"成功登录: 第 {accepted.line_number} 行 / "
                        f"{_format_time(accepted.timestamp)} / {accepted.username}",
                        f"此前失败: {len(prior)} 次，涉及账号 {_usernames(prior)}",
                        f"失败时间范围: {_format_time(prior[0].timestamp)} ~ "
                        f"{_format_time(prior[-1].timestamp)}",
                        f"失败日志行号: {_format_line_numbers(prior)}",
                    ),
                    line_numbers=tuple(
                        [event.line_number for event in prior] + [accepted.line_number]
                    ),
                    recommendation=(
                        "按账号失陷预案处理：立即隔离主机、终止可疑会话、封禁来源 IP、"
                        "轮换该账号凭据并检查持久化与横向移动痕迹。"
                    ),
                )
            )
            last_alert_at[accepted.username] = accepted.timestamp

    return alerts


def detect(
    events: Sequence[AuthEvent], config: Optional[DetectionConfig] = None
) -> Tuple[Alert, ...]:
    """执行全部规则，按严重级别降序、时间升序返回告警。"""

    active_config = config or DetectionConfig()
    ordered = sorted(events, key=lambda item: (item.timestamp, item.line_number))
    alerts: List[Alert] = []
    alerts.extend(_detect_brute_force(ordered, active_config))
    alerts.extend(_detect_user_enumeration(ordered, active_config))
    alerts.extend(_detect_success_after_failure(ordered, active_config))

    alerts.sort(
        key=lambda alert: (
            -int(alert.severity),
            alert.first_seen,
            alert.line_numbers[0] if alert.line_numbers else 0,
        )
    )
    return tuple(alerts)
