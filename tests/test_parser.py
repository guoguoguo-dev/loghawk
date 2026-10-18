"""解析器单元测试。"""

import gzip
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from loghawk.parser import parse_file, parse_lines

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ParserTests(unittest.TestCase):
    def test_parse_invalid_user_failure(self):
        line = (
            "Oct 18 09:12:05 web01 sshd[1201]: Failed password for invalid user "
            "admin from 198.51.100.23 port 55221 ssh2\n"
        )
        result = parse_lines([line], default_year=2026)

        self.assertEqual(result.total_lines, 1)
        self.assertEqual(result.ignored_lines, 0)
        self.assertEqual(result.event_count, 1)

        event = result.events[0]
        self.assertEqual(event.timestamp, datetime(2026, 10, 18, 9, 12, 5))
        self.assertEqual(event.host, "web01")
        self.assertEqual(event.pid, 1201)
        self.assertEqual(event.action, "failed")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.source_ip, "198.51.100.23")
        self.assertEqual(event.port, 55221)
        self.assertEqual(event.auth_method, "password")
        self.assertTrue(event.invalid_user)

    def test_parse_sshd_session_process_name(self):
        line = (
            "Oct 18 09:12:05 web01 sshd-session[1201]: Failed password for root "
            "from 198.51.100.23 port 55221 ssh2\n"
        )
        event = parse_lines([line], default_year=2026).events[0]
        self.assertEqual(event.pid, 1201)
        self.assertEqual(event.username, "root")

    def test_parse_accepted_publickey_with_fingerprint(self):
        line = (
            "Oct 18 08:12:01 web01 sshd[1101]: Accepted publickey for deploy "
            "from 203.0.113.24 port 50222 ssh2: RSA SHA256:AAAA\n"
        )
        event = parse_lines([line], default_year=2026).events[0]

        self.assertEqual(event.action, "accepted")
        self.assertEqual(event.username, "deploy")
        self.assertEqual(event.auth_method, "publickey")
        self.assertFalse(event.invalid_user)

    def test_parse_ipv6_source(self):
        line = (
            "Oct 18 09:12:05 web01 sshd[1201]: Failed password for root "
            "from 2001:db8::1 port 55221 ssh2\n"
        )
        event = parse_lines([line], default_year=2026).events[0]
        self.assertEqual(event.source_ip, "2001:db8::1")

    def test_ignores_unrelated_and_malformed_lines(self):
        lines = [
            "Oct 18 08:00:01 web01 sshd[1001]: Server listening on 0.0.0.0 port 22.\n",
            "this is not syslog\n",
            "Oct 18 09:12:05 web01 sshd[1201]: Failed password for root from "
            "not-an-ip port 55221 ssh2\n",
            "Oct 18 09:12:06 web01 sshd[1202]: Accepted password for alice from "
            "203.0.113.24 port 50001 ssh2\n",
        ]
        result = parse_lines(lines, default_year=2026)
        self.assertEqual(result.total_lines, 4)
        self.assertEqual(result.ignored_lines, 3)
        self.assertEqual(result.event_count, 1)

    def test_events_are_sorted_by_timestamp(self):
        lines = [
            "Oct 18 10:00:00 web01 sshd[1]: Accepted password for b from "
            "203.0.113.2 port 2 ssh2\n",
            "Oct 18 09:00:00 web01 sshd[1]: Accepted password for a from "
            "203.0.113.1 port 1 ssh2\n",
        ]
        result = parse_lines(lines, default_year=2026)
        self.assertEqual([event.username for event in result.events], ["a", "b"])

    def test_gzip_input(self):
        line = (
            "Oct 18 09:12:05 web01 sshd[1201]: Failed password for root "
            "from 198.51.100.23 port 55221 ssh2\n"
        )
        handle = tempfile.NamedTemporaryFile(
            mode="wb", suffix=".log.gz", dir=PROJECT_ROOT, delete=False
        )
        path = Path(handle.name)
        handle.close()
        try:
            with gzip.open(path, "wt", encoding="utf-8") as gzip_handle:
                gzip_handle.write(line)
            result = parse_file(path, default_year=2026)
        finally:
            path.unlink(missing_ok=True)

        self.assertEqual(result.event_count, 1)
        self.assertEqual(result.events[0].source_ip, "198.51.100.23")

    def test_empty_input(self):
        result = parse_lines([], default_year=2026)
        self.assertEqual(result.total_lines, 0)
        self.assertEqual(result.event_count, 0)
        self.assertEqual(result.ignored_lines, 0)


if __name__ == "__main__":
    unittest.main()
