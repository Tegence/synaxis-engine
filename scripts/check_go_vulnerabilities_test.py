import copy
import datetime
import json
import subprocess
import unittest
from unittest import mock

import check_go_vulnerabilities as gate


class VulnerabilityGateTest(unittest.TestCase):
    def setUp(self):
        self.today = datetime.date(2026, 11, 6)
        self.dependency = {"Path": gate.MCP_MODULE, "Version": "v1.4.0"}
        self.advisory = {
            "id": gate.ADVISORY,
            "affected": [{
                "package": {"name": gate.MCP_MODULE, "ecosystem": "Go"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                "ecosystem_specific": {"imports": [{
                    "path": gate.TRANSPORT_PACKAGE,
                    "symbols": sorted(gate.AFFECTED_SYMBOLS),
                }]},
            }],
        }
        self.finding = {
            "osv": gate.ADVISORY,
            "trace": [
                {"module": gate.MCP_MODULE, "version": "v1.4.0",
                 "package": gate.TRANSPORT_PACKAGE, "function": "NewStreamableHTTP"},
                {"module": gate.MCP_MODULE, "version": "v1.4.0",
                 "package": gate.MCP_MODULE + "/client", "function": "NewStreamableHttpClient"},
                {"module": gate.ENGINE_MODULE, "package": gate.ENGINE_PACKAGE,
                 "function": "dial", "receiver": "*Upstream"},
            ],
        }
        self.config = {
            "protocol_version": "v1.0.0", "scanner_name": "govulncheck",
            "scanner_version": "v1.9.0", "scan_level": "symbol", "scan_mode": "source",
            "db": "https://vuln.go.dev",
        }
        self.sbom = {"roots": [gate.ENGINE_PACKAGE], "modules": [{"path": gate.ENGINE_MODULE}]}

    def parse(self, output):
        return gate.parse_scan(output, gate.ENGINE_MODULE, "https://vuln.go.dev")

    def assess(self, finding=None, module=gate.ENGINE_MODULE, today=None):
        gate.require_local_mitigation(
            finding or self.finding, module, self.dependency, self.advisory,
            today or self.today,
        )

    def test_exact_guarded_finding_and_close_cleanup_are_allowed(self):
        self.assess()
        self.finding["trace"][0].update(function="Close", receiver="*StreamableHTTP")
        self.finding["trace"][-1]["function"] = "withConn"
        self.assess()

    def test_other_findings_versions_modules_and_paths_fail_closed(self):
        for field, value in [("osv", "GO-2026-9999"), ("fixed_version", "v1.4.1")]:
            with self.subTest(field=field):
                finding = copy.deepcopy(self.finding)
                finding[field] = value
                with self.assertRaises(gate.GateError):
                    self.assess(finding)
        for key, value in [("version", "v1.4.1"), ("module", "other/module"),
                           ("package", gate.MCP_MODULE + "/other"), ("function", "Other")]:
            with self.subTest(frame_field=key):
                finding = copy.deepcopy(self.finding)
                finding["trace"][0][key] = value
                with self.assertRaises(gate.GateError):
                    self.assess(finding)
        for field, value in [("function", "unguardedDial"), ("receiver", "*Other"),
                             ("package", gate.ENGINE_MODULE + "/cmd/engine")]:
            with self.subTest(call_site=field):
                finding = copy.deepcopy(self.finding)
                finding["trace"][-1][field] = value
                with self.assertRaises(gate.GateError):
                    self.assess(finding)
        with self.assertRaises(gate.GateError):
            self.assess(module="synaxis/platform")

    def test_advisory_fix_metadata_drift_expiry_and_replacement_fail(self):
        with self.assertRaises(gate.GateError):
            self.assess(today=datetime.date(2026, 11, 13))
        with self.assertRaises(gate.GateError):
            self.assess(today=datetime.date(2026, 11, 14))
        self.dependency["Replace"] = {"Path": "../local-sdk"}
        with self.assertRaises(gate.GateError):
            self.assess()
        del self.dependency["Replace"]
        for mutation in ("fix", "withdrawn", "symbols"):
            with self.subTest(mutation=mutation):
                original = copy.deepcopy(self.advisory)
                if mutation == "fix":
                    self.advisory["affected"][0]["ranges"][0]["events"].append({"fixed": "1.4.1"})
                elif mutation == "withdrawn":
                    self.advisory["withdrawn"] = "2026-11-06T00:00:00Z"
                else:
                    self.advisory["affected"][0]["ecosystem_specific"]["imports"][0]["symbols"].append("Other")
                with self.assertRaises(gate.GateError):
                    self.assess()
                self.advisory = original

    def test_scanner_stream_is_not_json_lines_and_metadata_is_not_a_finding(self):
        messages = [{"config": self.config}, {"SBOM": self.sbom},
                    {"osv": self.advisory}, {"finding": self.finding}]
        advisories, findings = self.parse("\n".join(json.dumps(x, indent=2) for x in messages))
        self.assertEqual(advisories, {gate.ADVISORY: self.advisory})
        self.assertEqual(findings, [self.finding])
        advisories, findings = self.parse("\n".join(json.dumps(x) for x in messages[:-1]))
        self.assertEqual(findings, [])

    def test_malformed_unknown_or_incomplete_scan_fails(self):
        prefix = json.dumps({"config": self.config})
        sbom = json.dumps({"SBOM": self.sbom})
        for output in ("", "{", prefix, sbom + prefix, prefix + sbom + "{",
                       prefix + sbom + '{"unknown":{}}', prefix + sbom + '{"finding":{"osv":"X","trace":[]}}'):
            with self.subTest(output=output):
                with self.assertRaises(gate.GateError):
                    self.parse(output)

    def test_conflicting_advisory_or_wrong_scan_identity_fails(self):
        messages = [{"config": self.config}, {"SBOM": self.sbom}, {"osv": self.advisory}]
        self.parse("\n".join(json.dumps(x) for x in messages + [{"osv": self.advisory}]))
        for invalid in (messages + [{"osv": dict(self.advisory, withdrawn="2026-11-06T00:00:00Z")}],
                        [{"config": dict(self.config, db="file:///old-db")}] + messages[1:],
                        [messages[0], {"SBOM": {"roots": ["other/module"], "modules": [{"path": "other/module"}]}}]):
            with self.subTest(messages=invalid):
                with self.assertRaises(gate.GateError):
                    self.parse("\n".join(json.dumps(x) for x in invalid))

    def test_mixed_informational_and_called_trace_fails(self):
        for index in (0, 1, 2):
            finding = copy.deepcopy(self.finding)
            del finding["trace"][index]["function"]
            finding["trace"][index].pop("receiver", None)
            messages = [{"config": self.config}, {"SBOM": self.sbom},
                        {"osv": self.advisory}, {"finding": finding}]
            with self.subTest(index=index):
                with self.assertRaises(gate.GateError):
                    self.parse("\n".join(json.dumps(x) for x in messages))

    def test_scanner_process_error_is_never_a_mitigation(self):
        with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 2, "{}", "scanner failed")):
            with self.assertRaises(gate.GateError):
                gate.run_checked(["go", "run", "scanner"])

    def test_regressions_must_really_run_pass_and_never_skip(self):
        events = []
        for name in gate.REGRESSION_TESTS:
            events.extend({"Action": action, "Package": gate.ENGINE_PACKAGE, "Test": name}
                          for action in ("run", "pass"))
        encode = lambda values: "\n".join(json.dumps(x) for x in values)
        gate.require_regressions(encode(events))
        for invalid in ([], events[:-1], events + [{"Action": "skip", "Test": "case"}],
                        events + [{"Action": "fail", "Test": "case"}]):
            with self.subTest(events=invalid):
                with self.assertRaises(gate.GateError):
                    gate.require_regressions(encode(invalid))


if __name__ == "__main__":
    unittest.main()
