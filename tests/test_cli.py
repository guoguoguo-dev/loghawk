"""CLI 端到端测试。"""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from loghawk.cli import main

ROOT = Path(__file__).resolve().parents[1]
DEMO_LOG = ROOT / "demo" / "auth.log"


def run_cli(args):
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(args, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


class Cp1252Stream(io.StringIO):
    """模拟 Windows 上只能写 cp1252 的输出流。"""

    encoding = "cp1252"

    def write(self, value):
        value.encode(self.encoding)
        return super().write(value)


class CliTests(unittest.TestCase):
    def test_text_report_finds_three_rules(self):
        code, output, _ = run_cli([str(DEMO_LOG)])

        self.assertEqual(code, 1)
        self.assertIn("LH-001", output)
        self.assertIn("LH-002", output)
        self.assertIn("LH-003", output)
        self.assertIn("共 3 条告警", output)

    def test_json_report_is_machine_readable(self):
        code, output, _ = run_cli([str(DEMO_LOG), "--format", "json"])
        payload = json.loads(output)

        self.assertEqual(code, 1)
        self.assertEqual(payload["tool"]["name"], "LogHawk")
        self.assertEqual(payload["summary"]["total"], 3)
        self.assertEqual(payload["summary"]["by_severity"]["CRITICAL"], 1)
        self.assertEqual(len(payload["alerts"]), 3)
        self.assertEqual(payload["alerts"][0]["rule_id"], "LH-002")

    def test_fail_on_never_returns_zero(self):
        code, _, _ = run_cli([str(DEMO_LOG), "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_min_severity_filters_output(self):
        code, output, _ = run_cli(
            [str(DEMO_LOG), "--format", "json", "--min-severity", "CRITICAL"]
        )
        payload = json.loads(output)

        self.assertEqual(code, 1)
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["alerts"][0]["rule_id"], "LH-002")

    def test_text_output_falls_back_on_cp1252_console(self):
        stdout = Cp1252Stream()
        stderr = io.StringIO()
        code = main(
            [str(DEMO_LOG), "--fail-on", "never"],
            stdout=stdout,
            stderr=stderr,
        )

        self.assertEqual(code, 0)
        self.assertIn("LogHawk", stdout.getvalue())

    def test_json_output_is_ascii_safe_on_cp1252_console(self):
        stdout = Cp1252Stream()
        stderr = io.StringIO()
        code = main(
            [str(DEMO_LOG), "--format", "json", "--fail-on", "never"],
            stdout=stdout,
            stderr=stderr,
        )
        payload = json.loads(stdout.getvalue())

        self.assertEqual(code, 0)
        self.assertIn("\\u", stdout.getvalue())
        self.assertEqual(payload["alerts"][0]["title"], "暴力破解后登录成功")

    def test_missing_file_returns_two(self):
        code, _, error = run_cli(["does-not-exist.log"])
        self.assertEqual(code, 2)
        self.assertIn("无法读取输入日志", error)

    def test_stdin_input(self):
        log_text = DEMO_LOG.read_text(encoding="utf-8")
        with mock.patch("sys.stdin", new=io.StringIO(log_text)):
            code, output, _ = run_cli(["-", "--format", "json"])
        payload = json.loads(output)

        self.assertEqual(code, 1)
        self.assertEqual(payload["input"]["source"], "<stdin>")
        self.assertEqual(payload["summary"]["total"], 3)

    def test_unrecognized_log_warns_and_exits_zero(self):
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", dir=ROOT, delete=False, encoding="utf-8"
        )
        path = Path(handle.name)
        try:
            handle.write("not an auth log\n")
            handle.close()
            code, output, error = run_cli([str(path)])
        finally:
            handle.close()
            path.unlink(missing_ok=True)

        self.assertEqual(code, 0)
        self.assertIn("未识别到 SSH 认证事件", error)
        self.assertIn("共 0 条告警", output)

    def test_invalid_year_is_rejected(self):
        with self.assertRaises(SystemExit) as context:
            main([str(DEMO_LOG), "--year", "1900"])
        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
