#!/usr/bin/env python3
"""Run the full live Go scan, with one temporary, regression-verified mitigation.

Run from the module directory. See SECURITY.md for GO-2026-6911 and removal.
There is no suppression flag, saved database, or environment expiry override.
"""

import datetime
import json
import os
import subprocess
import sys

ADVISORY = "GO-2026-6911"
MCP_MODULE = "github.com/mark3labs/mcp-go"
TRANSPORT_PACKAGE = MCP_MODULE + "/client/transport"
ENGINE_MODULE = "narthex/backend"
ENGINE_PACKAGE = ENGINE_MODULE + "/internal/engine"
REVIEW_BY = datetime.date(2026, 11, 13)
AFFECTED_SYMBOLS = {
    "NewStreamableHTTP", "StreamableHTTP.Close", "StreamableHTTP.SendNotification",
    "StreamableHTTP.SendRequest", "StreamableHTTP.SetRequestHandler",
}
REGRESSION_TESTS = {
    "TestUpstreamMCPRedirectRejectsCrossOrigin",
    "TestUpstreamMCPRedirectAllowsSameOrigin",
    "TestUpstreamMCPRedirectRetainsSafetyChecks",
}


class GateError(Exception):
    pass


def decode_stream(output):
    """govulncheck emits a sequence of pretty-printed objects, not JSONL."""
    decoder = json.JSONDecoder()
    index = 0
    messages = []
    try:
        while index < len(output):
            while index < len(output) and output[index].isspace():
                index += 1
            if index == len(output):
                break
            value, index = decoder.raw_decode(output, index)
            if not isinstance(value, dict):
                raise GateError("non-object JSON message")
            messages.append(value)
    except ValueError as error:
        raise GateError("invalid or truncated JSON stream") from error
    if not messages:
        raise GateError("empty JSON stream")
    return messages


def parse_scan(output, module, database):
    messages = decode_stream(output)
    config = messages[0].get("config", {})
    expected = {
        "protocol_version": "v1.0.0", "scanner_name": "govulncheck",
        "scanner_version": "v1.9.0", "scan_level": "symbol", "scan_mode": "source",
        "db": database,
    }
    if any(config.get(key) != value for key, value in expected.items()):
        raise GateError("unexpected govulncheck protocol, version, or scan scope")
    counts = {"config": 0, "SBOM": 0}
    advisories, findings = {}, []
    for message in messages:
        if len(message) != 1:
            raise GateError("invalid scanner message")
        kind, value = next(iter(message.items()))
        if kind not in {"config", "SBOM", "progress", "osv", "finding"} or not isinstance(value, dict):
            raise GateError("unrecognized scanner message")
        if kind in counts:
            counts[kind] += 1
        if kind == "SBOM":
            roots = value.get("roots", [])
            if (not roots or any(not isinstance(root, str) or
                                not (root == module or root.startswith(module + "/")) for root in roots)
                    or not any(item.get("path") == module for item in value.get("modules", []))):
                raise GateError("scanner did not report the requested module's packages")
        if kind == "osv":
            if not isinstance(value.get("id"), str) or not value["id"]:
                raise GateError("advisory has no ID")
            # The scanner can repeat identical OSV metadata for multiple
            # affected modules. Conflicting metadata must not overwrite it.
            if value["id"] in advisories and advisories[value["id"]] != value:
                raise GateError("scanner reported conflicting advisory metadata")
            advisories[value["id"]] = value
        if kind == "finding":
            trace = value.get("trace")
            if not isinstance(value.get("osv"), str) or not value["osv"] or not isinstance(trace, list) or not trace:
                raise GateError("finding has no advisory or trace")
            for frame in trace:
                if not isinstance(frame, dict) or not frame.get("module"):
                    raise GateError("finding has an invalid frame")
                if any(not isinstance(frame.get(key, ""), str) for key in
                       ("module", "version", "package", "function", "receiver")):
                    raise GateError("finding has an invalid frame field")
                if frame.get("function") and not frame.get("package"):
                    raise GateError("finding function has no package")
                if frame.get("receiver") and not frame.get("function"):
                    raise GateError("finding receiver has no function")
            called = bool(trace[0].get("function"))
            if (not called and len(trace) != 1) or (called and any(not frame.get("function") for frame in trace)):
                raise GateError("finding mixes informational and called frames")
            findings.append(value)
    if counts != {"config": 1, "SBOM": 1}:
        raise GateError("scanner config or SBOM is missing or duplicated")
    if any(finding["osv"] not in advisories for finding in findings):
        raise GateError("finding has no advisory metadata")
    return advisories, findings


def require_local_mitigation(finding, module, dependency, advisory, today):
    """Accept only the reviewed SDK symbols reached through Engine's guard."""
    first = finding["trace"][0]
    symbol = first.get("function", "")
    if first.get("receiver"):
        symbol = first["receiver"].lstrip("*") + "." + symbol
    if (finding["osv"] != ADVISORY or module != ENGINE_MODULE
            or first.get("module") != MCP_MODULE or first.get("version") != "v1.4.0"
            or first.get("package") != TRANSPORT_PACKAGE or symbol not in AFFECTED_SYMBOLS
            or finding.get("fixed_version")):
        raise GateError("reachable vulnerability has no reviewed local mitigation")
    if today >= REVIEW_BY:
        raise GateError(f"{ADVISORY} mitigation review expired on {REVIEW_BY} UTC")
    if (dependency.get("Path") != MCP_MODULE or dependency.get("Version") != "v1.4.0"
            or dependency.get("Replace")):
        raise GateError("mitigation requires the original mcp-go v1.4.0 dependency")
    expected_affected = [{
        "package": {"name": MCP_MODULE, "ecosystem": "Go"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        "ecosystem_specific": {"imports": [{"path": TRANSPORT_PACKAGE,
                                            "symbols": sorted(AFFECTED_SYMBOLS)}]},
    }]
    # Normalize only symbol ordering. A fix, changed affected range/package or
    # symbol, or withdrawal requires a fresh review rather than an old waiver.
    affected = json.loads(json.dumps(advisory.get("affected", [])))
    for item in affected:
        for imported in item.get("ecosystem_specific", {}).get("imports", []):
            imported["symbols"] = sorted(imported.get("symbols", []))
    if advisory.get("id") != ADVISORY or advisory.get("withdrawn") or affected != expected_affected:
        raise GateError("advisory metadata changed; review mitigation and any upstream fix")
    engine_frames = []
    for frame in finding["trace"]:
        if frame.get("module") == ENGINE_MODULE and frame.get("package") == ENGINE_PACKAGE:
            engine_frames.append(frame)
        elif (engine_frames or frame.get("module") != MCP_MODULE
              or frame.get("version") != "v1.4.0"
              or frame.get("package") not in {TRANSPORT_PACKAGE, MCP_MODULE + "/client"}):
            raise GateError("vulnerable symbol has a new or unreviewed call path")
    # Close is deferred by withConn, so its scanner trace does not include dial.
    entry = "withConn" if symbol == "StreamableHTTP.Close" else "dial"
    if not engine_frames or engine_frames[0].get("function") != entry or engine_frames[0].get("receiver") != "*Upstream":
        raise GateError("vulnerable symbol does not enter through the guarded Upstream call site")


def require_regressions(output):
    ran, passed = set(), set()
    for event in decode_stream(output):
        if event.get("Action") in {"fail", "skip"}:
            raise GateError("redirect mitigation regression failed or skipped")
        if event.get("Package") == ENGINE_PACKAGE:
            if event.get("Action") == "run":
                ran.add(event.get("Test"))
            if event.get("Action") == "pass":
                passed.add(event.get("Test"))
    if not REGRESSION_TESTS <= ran or not REGRESSION_TESTS <= passed:
        raise GateError("redirect mitigation regression evidence is missing")


def run_checked(command):
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode:
        if result.stdout:
            print(result.stdout, end="")
        raise GateError(f"command failed ({result.returncode}): {' '.join(command)}")
    return result.stdout


def main():
    module = json.loads(run_checked(["go", "list", "-m", "-json"]))["Path"]
    database = os.environ.get("GOVULNCHECK_DB", "https://vuln.go.dev")
    print(f"Scanning {module} with govulncheck v1.9.0 against {database}", flush=True)
    # JSON mode returns zero even for findings. We enforce symbol-level failure
    # ourselves, matching govulncheck's default text gate, after a complete scan.
    advisories, findings = parse_scan(run_checked([
        "go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.9.0", "-json",
        "-db", database, "-scan=symbol", "-mode=source", "./...",
    ]), module, database)
    called = []
    for finding in findings:
        reachable = bool(finding["trace"][0].get("function"))
        label = "REACHABLE" if reachable else "INFORMATIONAL (not called)"
        print(f"{label}: {json.dumps(finding, sort_keys=True)}")
        if reachable:
            called.append(finding)
    if called:
        dependency = json.loads(run_checked(["go", "list", "-m", "-json", MCP_MODULE]))
        for finding in called:
            require_local_mitigation(finding, module, dependency, advisories[finding["osv"]],
                                     datetime.datetime.now(datetime.timezone.utc).date())
        expression = "^(" + "|".join(sorted(REGRESSION_TESTS)) + ")$"
        evidence = run_checked(["go", "test", "-json", "-count=1", "./internal/engine", "-run", expression])
        print(evidence, end="")
        require_regressions(evidence)
        print(f"PASS WITH LOCAL MITIGATION: {ADVISORY} remains reported upstream; "
              f"the reviewed Engine redirect guard passed all three regressions. "
              f"Review required before {REVIEW_BY} UTC. See SECURITY.md.")
    else:
        print("PASS: no reachable vulnerabilities reported by the full symbol scan.")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Go vulnerability gate: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
