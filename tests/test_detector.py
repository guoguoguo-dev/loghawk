"""检测规则单元测试。"""

import unittest
from datetime import datetime, timedelta

from loghawk.detector import (
    RULE_BRUTE_FORCE,
    RULE_SUCCESS_AFTER_FAILURE,
    RULE_USER_ENUMERATION,
    detect,
)
from loghawk.models import AuthEvent, DetectionConfig

BASE = datetime(2026, 10, 18, 9, 0, 0)


def make_event(
    minute,
    line,
    action="failed",
    username="root",
    source_ip="198.51.100.23",
    invalid_user=False,
):
    return AuthEvent(
        timestamp=BASE + timedelta(minutes=minute),
        host="web01",
        pid=1000 + line,
        action=action,
        username=username,
        source_ip=source_ip,
        port=50000 + line,
        auth_method="password",
        invalid_user=invalid_user,
        line_number=line,
        raw="synthetic",
    )


class DetectorTests(unittest.TestCase):
    def test_detects_brute_force(self):
        events = [make_event(index, line=index + 1) for index in range(5)]
        alerts = detect(events, DetectionConfig())

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, RULE_BRUTE_FORCE)
        self.assertEqual(alert.severity.name, "HIGH")
        self.assertEqual(alert.source_ip, "198.51.100.23")
        self.assertEqual(len(alert.line_numbers), 5)

    def test_does_not_alert_below_threshold(self):
        events = [make_event(index, line=index + 1) for index in range(4)]
        self.assertEqual(detect(events, DetectionConfig()), ())

    def test_does_not_cross_ips(self):
        events = [make_event(0, 1, source_ip="198.51.100.1")]
        events += [make_event(0, 2, source_ip="198.51.100.2")]
        events += [make_event(1, 3, source_ip="198.51.100.1")]
        events += [make_event(1, 4, source_ip="198.51.100.2")]
        self.assertEqual(detect(events, DetectionConfig()), ())

    def test_detects_success_after_failures(self):
        events = [make_event(index, line=index + 1) for index in range(5)]
        events.append(
            make_event(6, line=6, action="accepted", username="root")
        )
        alerts = detect(events, DetectionConfig())

        rules = {alert.rule_id for alert in alerts}
        self.assertIn(RULE_SUCCESS_AFTER_FAILURE, rules)
        critical = [a for a in alerts if a.rule_id == RULE_SUCCESS_AFTER_FAILURE][0]
        self.assertEqual(critical.severity.name, "CRITICAL")
        self.assertEqual(critical.line_numbers[-1], 6)
        self.assertEqual(len(critical.line_numbers), 6)

    def test_detects_success_for_a_second_account(self):
        events = [make_event(index, line=index + 1) for index in range(5)]
        events.append(make_event(6, line=6, action="accepted", username="root"))
        events.append(make_event(7, line=7, action="accepted", username="alice"))
        critical = [
            alert
            for alert in detect(events, DetectionConfig())
            if alert.rule_id == RULE_SUCCESS_AFTER_FAILURE
        ]
        self.assertEqual([alert.username for alert in critical], ["root", "alice"])

    def test_does_not_alert_success_outside_lookback(self):
        events = [make_event(index, line=index + 1) for index in range(5)]
        events.append(
            make_event(20, line=6, action="accepted", username="root")
        )
        rules = {alert.rule_id for alert in detect(events, DetectionConfig())}
        self.assertNotIn(RULE_SUCCESS_AFTER_FAILURE, rules)

    def test_detects_username_enumeration(self):
        events = [
            make_event(0, 1, username="admin", invalid_user=True),
            make_event(1, 2, username="test", invalid_user=True),
            make_event(2, 3, username="oracle", invalid_user=True),
        ]
        alerts = detect(events, DetectionConfig())

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, RULE_USER_ENUMERATION)
        self.assertEqual(alerts[0].severity.name, "MEDIUM")

    def test_no_alert_for_benign_logins(self):
        events = [
            make_event(0, 1, action="accepted", username="alice", source_ip="203.0.113.9"),
            make_event(1, 2, action="accepted", username="bob", source_ip="203.0.113.10"),
        ]
        self.assertEqual(detect(events, DetectionConfig()), ())

    def test_critical_alert_sorts_first(self):
        events = [make_event(index, line=index + 1) for index in range(5)]
        events.append(
            make_event(6, line=6, action="accepted", username="root")
        )
        events.extend(
            [
                make_event(
                    0,
                    7,
                    username="x",
                    source_ip="203.0.113.77",
                    invalid_user=True,
                ),
                make_event(
                    1,
                    8,
                    username="y",
                    source_ip="203.0.113.77",
                    invalid_user=True,
                ),
                make_event(
                    2,
                    9,
                    username="z",
                    source_ip="203.0.113.77",
                    invalid_user=True,
                ),
            ]
        )
        alerts = detect(events, DetectionConfig())
        self.assertEqual(alerts[0].severity.name, "CRITICAL")

    def test_custom_thresholds(self):
        events = [make_event(index, line=index + 1) for index in range(3)]
        config = DetectionConfig(failed_threshold=3)
        alerts = detect(events, config)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, RULE_BRUTE_FORCE)


if __name__ == "__main__":
    unittest.main()
