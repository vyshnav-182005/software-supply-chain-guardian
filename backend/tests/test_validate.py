"""Run: .venv/Scripts/python -m tests.test_validate   (no network, no Docker, no API key, no scans)"""
import json
import os
import subprocess
import tempfile

os.environ["GUARDIAN_DATA_DIR"] = tempfile.mkdtemp()
os.environ["GROQ_API_KEY"] = ""
os.environ["GUARDIAN_LLM_API_KEY"] = ""

from app import db, report, validate  # noqa: E402


def git(cwd, *a):
    subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)


def make_scan():
    sid = db.create("https://github.com/acme/app")
    repo = db.DATA / "workspaces" / sid / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"mongodb": "^2.2.36"}}, indent=2))
    (repo / "Dockerfile").write_text("FROM alpine\nRUN npm install --omit=dev\n")
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, *validate.GIT_ID, "commit", "-qm", "init")
    up = {"id": "c1", "risk_id": "r1", "package": "bson", "version": "1.0.9", "action": "upgrade-parent", "band": "high",
          "title": "Upgrade mongodb 2.2.36 -> 3.1.13", "score_before": 7.8, "score_after": 0.0,
          "advisories_removed": ["GHSA-bson"], "cves_removed": [], "remaining": [],
          "packages": [{"package": "bson", "version": "1.0.9", "band": "high", "score_before": 7.8, "score_after": 0.0}],
          "change": {"package": "mongodb", "from": "2.2.36", "to": "3.1.13", "spec_from": "^2.2.36", "spec_to": "^3.1.13",
                     "field": "dependencies", "manifest": "package.json", "jump": "major"}}
    cfg = {"id": "c2", "risk_id": "r2", "package": "Dockerfile:1", "version": "", "action": "config", "band": "medium",
           "title": "Pin the base image by digest: Dockerfile:1", "score_before": 6.0, "score_after": 0.0,
           "advisories_removed": [], "cves_removed": [], "remaining": [], "change": None,
           "packages": [{"package": "Dockerfile:1", "version": "", "band": "medium", "score_before": 6.0, "score_after": 0.0}]}
    results = {
        "checkout": {"repo": "app"},
        "discovery": {"components": [{"name": "bson", "version": "1.0.9"}, {"name": "mongodb", "version": "2.2.36"}],
                      "stats": {"components": 2}},
        "vulnerability": {"findings": [{"name": "bson", "version": "1.0.9", "advisory_id": "GHSA-bson", "severity": "high"}]},
        "change_detection": {"findings": [{"id": "s1", "rule": "base-image", "severity": "medium", "title": "t",
                                           "evidence": {"file": "Dockerfile", "line": 1}}]},
        "investigate": {"config_items": [{"component": "config:Dockerfile:1", "rule": "base-image", "file": "Dockerfile",
                                          "line": 1, "text": "FROM alpine"}]},
        "prioritize": {"risks": [
            {"id": "r1", "package": "bson", "version": "1.0.9", "band": "high", "final_score": 7.8, "formula": "f",
             "advisories": [{"id": "GHSA-bson"}], "labels": [], "path": ["app", "mongodb@2.2.36", "bson@1.0.9"],
             "reachability": "unknown", "component": "pkg:npm/bson@1.0.9"},
            {"id": "r2", "package": "Dockerfile:1", "version": "", "band": "medium", "final_score": 6.0, "formula": "f",
             "advisories": [], "labels": ["repo config"], "path": [], "reachability": "unknown",
             "component": "config:Dockerfile:1"},
            {"id": "r3", "package": "minimist", "version": "0.0.8", "band": "low", "final_score": 2.0, "formula": "f",
             "advisories": [], "labels": [], "path": [], "reachability": "unknown", "component": "x"}]},
        "remediate": {"cards": [up, cfg]},
    }
    db.update(sid, lambda d: d.update(status="completed", commit_sha="abc123def456", results=results))
    return sid, repo


if __name__ == "__main__":
    sid, repo = make_scan()
    # fakes: no npm, no Docker, no network, no osv-scanner
    validate.relock = lambda project, update: (True, "relocked")
    validate.docker_ready = lambda: False
    validate.resolve_image_digest = lambda image: "sha256:" + "a" * 64
    after = {"components": [{"name": "bson", "version": "1.0.4"}, {"name": "mongodb", "version": "3.1.13"}],
             "vulnerabilities": [], "suspicious": [], "risks": [], "risk_counts": {"high": 0}, "stats": {"components": 2}}
    validate.rescan = lambda scan, root, art: after

    validate.run(sid, "c1")
    v = db.validations(sid)["c1"]
    assert v["status"] == "fixed_untested", v                       # fixed; build skipped because Docker is off
    fix = db.DATA / "workspaces" / sid / "fix-c1"
    assert json.loads((fix / "package.json").read_text())["dependencies"]["mongodb"] == "^3.1.13"
    assert json.loads((repo / "package.json").read_text())["dependencies"]["mongodb"] == "^2.2.36"  # original untouched
    assert v["branch"] == "fix/mongodb-3.1.13" and "Docker is not running" in v["build"]["detail"]
    assert v["comparison"]["sbom_diff"]["changed"] == ["bson 1.0.9 -> 1.0.4", "mongodb 2.2.36 -> 3.1.13"]
    assert [s["name"] for s in v["steps"]] == ["copy", "apply", "relock", "build_test", "rescan"]

    validate.run(sid, "c2")                                         # config fix: digest pinned, finding gone
    v2 = db.validations(sid)["c2"]
    assert v2["status"] == "verified", v2
    assert (db.DATA / "workspaces" / sid / "fix-c2" / "Dockerfile").read_text().startswith("FROM alpine@sha256:")

    after["vulnerabilities"] = [{"name": "bson", "version": "1.0.9", "advisory_id": "GHSA-bson", "severity": "high"}]
    validate.run(sid, "c1")                                         # advisory still there -> not fixed
    assert db.validations(sid)["c1"]["status"] == "not_fixed"

    # Report: decisions + validations -> before/after, remaining, audit trail, rule summary (no key)
    db.decide(sid, "c2", "approved", "reviewer", "")
    db.decide(sid, "c1", "rejected", "reviewer", "")
    rep = report.build(sid)
    f = rep["facts"]
    assert f["approved"] == 1 and f["rejected"] == 1 and f["validated"]["verified"] == 1
    assert [r["package"] for r in rep["remaining"]["resolved"]] == ["Dockerfile:1"]
    assert [r["package"] for r in rep["remaining"]["rejected"]] == ["bson@1.0.9"]
    assert [r["package"] for r in rep["remaining"]["accepted"]] == ["minimist@0.0.8"]
    assert f["risk_bands_before"] == {"critical": 0, "high": 1, "medium": 1, "low": 1}
    assert f["risk_bands_after"] == {"critical": 0, "high": 1, "medium": 0, "low": 1}
    assert rep["summary"]["source"] == "rule" and "Supply-chain report" in report.markdown(rep)
    # Combined: every approved fix together on fix/combined, remaining advisories explained
    db.decide(sid, "c1", "approved", "reviewer", "")
    after["vulnerabilities"] = [{"name": "marsdb", "version": "0.6.11", "advisory_id": "GHSA-m", "severity": "critical",
                                 "fixed_versions": [], "fix": None}]
    validate.run_combined(sid)
    cv = db.validations(sid)["combined"]
    assert cv["branch"] == "fix/combined" and len(cv["applied"]) == 2, cv
    assert cv["comparison"]["advisories_before"] == 1 and cv["comparison"]["advisories_after"] == 1
    assert cv["comparison"]["remaining"][0]["reason"] == "new: brought in by one of the upgrades"
    assert cv["status"] == "not_fixed"                                    # a new critical appeared
    comb = db.DATA / "workspaces" / sid / "fix-combined"
    assert json.loads((comb / "package.json").read_text())["dependencies"]["mongodb"] == "^3.1.13"
    assert (comb / "Dockerfile").read_text().startswith("FROM alpine@sha256:")
    assert report.build(sid)["facts"]["combined"]["advisories_after"] == 1
    from app.validate import merge_changes
    m = merge_changes([{"action": "upgrade", "change": {"manifest": "package.json", "field": "dependencies",
                                                        "package": "express-jwt", "to": "6.0.0"}},
                       {"action": "upgrade-all", "changes": [{"manifest": "package.json", "field": "dependencies",
                                                              "package": "express-jwt", "to": "8.4.1"}]}])
    assert len(m) == 1 and m[0]["to"] == "8.4.1"                          # shared parent: highest target wins
    print("validate ok")
