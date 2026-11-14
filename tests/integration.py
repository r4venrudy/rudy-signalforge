"""Exercise the public CLI with a separate exhaustive bounded reference model."""
from datetime import datetime, timedelta, timezone
from itertools import combinations
import json
from pathlib import Path
import random
import subprocess
import sys
from tempfile import TemporaryDirectory

runtime, binary, examples = sys.argv[1:]
examples = Path(examples)
checks = 0


def check(condition, detail):
    global checks
    if not condition:
        raise AssertionError(detail)
    checks += 1


def invoke(*args, status=0):
    proc = subprocess.run([runtime, binary, *map(str, args)], capture_output=True,
                          encoding="utf-8", timeout=20)
    check(proc.returncode == status, (args, proc.returncode, proc.stderr))
    if status == 2:
        check(not proc.stdout and proc.stderr.startswith("signalforge:"), proc)
        return None
    check(not proc.stderr, proc.stderr)
    return json.loads(proc.stdout)


def store(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def term(value):
    return [{"field": "kind", "op": "eq", "value": value}]


def make_event(index, clock, kind, group):
    ts = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=clock)).isoformat()
    return dict(ts=ts, source="auth", id=f"e{index}", fields={"kind": kind, "group": group})


fixture = invoke("test", examples/"rules.json", examples/"events.jsonl", examples/"expected.json")
check(fixture == dict(passed=True, expected=2, actual=2, missing=0, unexpected=0), fixture)
check(len(invoke("lint", examples/"rules.json")["rules"]) == 2, "fixture rules")

with TemporaryDirectory() as folder:
    rules, events, expected = (Path(folder) / name for name in ("rules.json", "events.jsonl", "expected.json"))
    sequence = dict(id="sequence", severity="high", type="sequence", by=["group"], seconds=4,
                    stages=[term("a"), term("a"), term("b")])
    threshold = dict(id="threshold", severity="low", type="threshold", by=["group"], seconds=4,
                     count=2, stages=[term("a")])
    store(rules, {"version": 1, "rules": [sequence, threshold]})
    rng = random.Random(20261114)
    for trial in range(16):
        idx = list(range(28))
        timeline = sorted(rng.randrange(22) for _ in idx)
        rows = [make_event(i, timeline[i], rng.choice("abc"), rng.choice(["x", "y"])) for i in idx]
        events.write_text("\r\n".join(map(json.dumps, rows)), encoding="utf-8")
        report = invoke("replay", rules, events)
        check(report["schemaVersion"] == 1, report)
        expected_hits = []
        for i, row in enumerate(rows):
            group = row["fields"]["group"]
            kind = row["fields"]["kind"]
            earlier = [j for j in idx[:i] if rows[j]["fields"]["group"] == group and
                       rows[j]["fields"]["kind"] == "a" and timeline[i] - timeline[j] <= 4]
            if kind == "b" and any(a < b for a, b in combinations(earlier, 2)):
                expected_hits.append(("sequence", i, group))
            if kind == "a" and len(earlier) == 1:
                expected_hits.append(("threshold", i, group))
        actual_hits = []
        for alert in report["alerts"]:
            evidence = [int(item["id"][1:]) for item in alert["evidence"]]
            check(evidence == sorted(set(evidence)), alert)
            check(all(rows[i]["fields"]["group"] == alert["group"][0] for i in evidence), alert)
            check(timeline[evidence[-1]] - timeline[evidence[0]] <= 4, alert)
            check([rows[i]["fields"]["kind"] for i in evidence] ==
                  (["a","a","b"] if alert["rule"] == "sequence" else ["a","a"]), alert)
            actual_hits.append((alert["rule"], evidence[-1], alert["group"][0]))
        check(actual_hits == expected_hits, (trial, expected_hits, actual_hits))

    store(expected, [])
    result = invoke("test", examples/"rules.json", examples/"events.jsonl", expected, status=3)
    check(result["unexpected"] == 2 and not result["passed"], result)
    fixture = json.loads((examples/"expected.json").read_text())
    store(expected, fixture + fixture[:1])
    check(invoke("test", examples/"rules.json", examples/"events.jsonl", expected, status=3)["missing"] == 1,
          "exact multiplicity")
    for data in (
        b"\n", b"\xff", b" " * 32769,
        b'{"source":"x","source":"y"}',
        json.dumps({**make_event(0, 0, "a", "x"), "ts": "2026-01-01T00:00:00"}).encode(),
        (json.dumps(make_event(1, 2, "a", "x")) + "\n" + json.dumps(make_event(2, 1, "a", "x"))).encode(),
        "\n".join([json.dumps(make_event(0, 0, "a", "x"))]*2).encode(),
        b'{"ts":"2026-01-01T00:00:00Z","source":"auth","id":"one","fields":{"kind":"a","kind":"b"}}',
    ):
        events.write_bytes(data)
        invoke("replay", rules, events, status=2)
    for variant in ({**threshold, "seconds": 0}, {**threshold, "by": ["group", "group"]},
                    {**threshold, "stages": [[{"field": "kind", "op": "script", "value": "a"}]]}):
        store(rules, {"version": 1, "rules": [variant]})
        invoke("lint", rules, status=2)
    store(rules, {"version": 1, "rules": [threshold, threshold]})
    invoke("lint", rules, status=2)

print(f"{checks} independent checks of replay and CLI behavior")
