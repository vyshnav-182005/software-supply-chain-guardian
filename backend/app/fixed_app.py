"""The fixed application: Approve applies the fix, then build, verify and run the fixed app.

One cumulative working copy per scan: workspaces/<scan>/fixed on branch fix/guardian. The scanned clone
(workspaces/<scan>/repo) is never modified.

  Approve  -> apply_card(): the card's change is written into the fixed copy on top of the earlier
              approved fixes and committed (one commit per card, so it can be rolled back alone).
              package.json edits never downgrade a version another fix already raised.
              Card status: applied | already_applied | apply_failed | manual.
  Build    -> build(): relock, `npm ci` + build in the Docker sandbox. If npm cannot resolve the tree or
              the build fails because of the code (not the sandbox), the most recent package fix is rolled
              back (git revert) and marked rolled_back with the log, and the rest is retried (max 3 times).
              Then: app smoke test, tests, rescan, original-vs-fixed comparison with a reason for every
              advisory that remains, a downloadable patch, and the fixed app started for real at
              http://localhost:3001 (Docker, port published to the host).
"""
import json
import re
import subprocess
import threading
import time
import traceback
from pathlib import Path

from . import db
from .agents.remediate import ver
from .validate import (APP_PORT, DOCKER, GIT_ID, LOCAL_APPS, NPM_BLAME, Step, _git, _rmtree, apply_change,
                       apply_config, remove_stray_venvs, runner_kind, stop_local,
                       build_and_test, detect_app, docker_ready, dry_run, explain_remaining, relock, rescan)

FIXED = "fixed"           # validations-table key for the build/run record
MAX_ROLLBACKS = 3
PACKAGE_ACTIONS = ("upgrade", "upgrade-parent", "upgrade-all", "relock", "override", "pin", "constrain")
_lock = threading.Lock()  # one change to the fixed copy at a time


def workdir(scan_id: str) -> Path:
    return db.DATA / "workspaces" / scan_id / "fixed"


def ensure_copy(scan_id: str) -> Path:
    dst = workdir(scan_id)
    if not (dst / ".git").exists():
        import shutil
        _rmtree(dst)
        shutil.copytree(db.DATA / "workspaces" / scan_id / "repo", dst, ignore=shutil.ignore_patterns("node_modules"))
        _git(dst, "checkout", "-q", "-b", "fix/guardian")
        # lockfiles generated at scan time are not in the repo: commit them as the baseline so the patch
        # and rollbacks only show what the fixes change
        locks = [p.relative_to(dst).as_posix() for p in dst.rglob("package-lock.json") if "node_modules" not in p.parts]
        if locks:
            _git(dst, "add", "-f", "--", *locks)
            _git(dst, *GIT_ID, "commit", "-q", "-m", "Guardian: baseline lockfiles (resolved at scan time)")
        _git(dst, "tag", "guardian-original")
    return dst


def _spec_version(spec: str | None):
    m = re.search(r"\d+(\.\d+){0,2}", spec or "")
    return ver(m.group(0)) if m else None


def without_downgrades(card: dict, root: Path) -> tuple[dict, list]:
    """Drop changes that would lower a version an earlier fix already raised (shared parents)."""
    kept, skipped = [], []
    for ch in card.get("changes") or ([card["change"]] if card.get("change") else []):
        manifest = root / ch["manifest"].replace("package-lock.json", "package.json")
        if ch.get("field") in (None, "lockfile", "requirements") or not manifest.is_file():
            kept.append(ch)
            continue
        data = json.loads(manifest.read_text(encoding="utf-8"))
        current = _spec_version((data.get(ch["field"]) or {}).get(ch["package"]))
        target = ver(str(ch["to"]))
        if current and target and current > target and current != _spec_version(ch.get("spec_from")):
            skipped.append(f"{ch['package']} is already at {current} from another fix")
        else:
            kept.append(ch)
    return {**card, "changes": kept, "change": kept[0] if kept else None}, skipped


def apply_card(scan_id: str, card_id: str) -> None:
    """Approve: write this card's change into the fixed copy and commit it."""
    rec = {"card_id": card_id, "status": "applying", "steps": []}
    db.save_validation(scan_id, card_id, rec)
    with _lock:
        try:
            res = db.get(scan_id)["results"]
            card = next(c for c in res["remediate"]["cards"] if c["id"] == card_id)
            root = ensure_copy(scan_id)
            if card["action"] in PACKAGE_ACTIONS:
                card2, skipped = without_downgrades(card, root)
                if not card2["changes"]:
                    rec.update(status="already_applied", reason="; ".join(skipped) or "Nothing to change")
                    return
                db.save_validation(scan_id, card_id, {**rec, "status": "checking", "reason": "dry run on the fixed copy"})
                check = dry_run(card2, root)  # with every fix applied so far: would npm accept this one too?
                if not check["ok"]:
                    vals = db.validations(scan_id)
                    culprits = [c["title"] for c in res["remediate"]["cards"] if vals.get(c["id"], {}).get("status") == "applied"
                                and any(ch.get("package") in check["blamed"] for ch in vals[c["id"]].get("changes") or [])]
                    rec.update(status="conflicts", reason=(f"Conflicts with {', '.join(culprits)}: " if culprits else
                                                           f"{check.get('tool', 'npm')} cannot install it: ") + check["reason"],
                               npm_log=check["log"], blamed=check["blamed"])
                    return
                applied = apply_change(card2, res, root)
            elif card["action"] == "config":
                applied = apply_config(card, res, root)
            else:
                applied = {"ok": False, "detail": "Needs a person: replace or remove the package by hand.", "manual": True}
            if not applied["ok"]:
                rec.update(status="manual" if applied.get("manual") or card["action"] in ("replace", "remove")
                           else "apply_failed", reason=applied["detail"])
                return
            _git(root, "add", "-u")  # tracked files only: never build output or node_modules
            if not _git(root, "diff", "--cached", "--name-only").strip():
                rec.update(status="already_applied", reason="The fixed copy already contains this change")
                return
            _git(root, *GIT_ID, "commit", "-q", "-m", f"Guardian fix {card_id}: {card['title']}")
            rec.update(status="applied", reason=applied["detail"], diff=applied.get("diff", ""),
                       changes=card2["changes"] if card["action"] in PACKAGE_ACTIONS else [],
                       commit=_git(root, "rev-parse", "HEAD").strip(), kind=applied["kind"],
                       projects=applied.get("projects"), updates=applied.get("updates"))
            stale = db.validations(scan_id).get(FIXED)
            if stale and stale.get("status") not in ("queued", "running"):  # the last build no longer matches
                db.save_validation(scan_id, FIXED, {**stale, "outdated": True})
        except Exception as e:
            traceback.print_exc()
            rec.update(status="apply_failed", reason=f"{type(e).__name__}: {str(e)[:300]}")
        finally:
            db.save_validation(scan_id, card_id, rec)


# ---------------------------------------------------------------- build, verify, run

def build(scan_id: str) -> None:
    rec = {"card_id": FIXED, "status": "running", "steps": [], "rollbacks": [],
           "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    db.save_validation(scan_id, FIXED, rec)
    step = Step(scan_id, FIXED, rec)
    with _lock:
        try:
            _build(scan_id, rec, step)
        except Exception as e:
            traceback.print_exc()
            rec.update(status="error", reason=f"{type(e).__name__}: {str(e)[:300]}")
        rec["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        db.save_validation(scan_id, FIXED, rec)


def _applied(scan_id: str, cards: list) -> list[tuple[dict, dict]]:
    vals = db.validations(scan_id)
    return [(c, vals[c["id"]]) for c in cards if vals.get(c["id"], {}).get("status") == "applied"]


def _undo(root: Path, val: dict) -> None:
    """Put back what one card changed in package.json (overrides entry removed, version restored).
    Done by editing, not `git revert`, so neighbouring changes from other fixes never conflict."""
    for ch in val.get("changes") or []:
        if ch.get("field") in (None, "lockfile"):
            continue  # lockfile-only fixes are undone by leaving them out of the next relock
        manifest = root / ch["manifest"].replace("package-lock.json", "package.json")
        if ch.get("field") == "requirements":
            from .agents import pydeps
            pydeps.undo_requirements(manifest, ch["package"], ch.get("spec_from"))
            continue
        data = json.loads(manifest.read_text(encoding="utf-8"))
        section = data.get(ch["field"]) or {}
        if ch["field"] == "overrides" or not ch.get("spec_from"):
            section.pop(ch["package"], None)
            if ch["field"] == "overrides" and not section:
                data.pop("overrides", None)
        else:
            section[ch["package"]] = ch["spec_from"]
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _commit_tracked(root: Path, message: str, extra: list[str] = ()) -> None:
    _git(root, "add", "-u")
    if extra:
        _git(root, "add", "-f", "--", *extra)
    if _git(root, "status", "--porcelain", "--untracked-files=no").strip():
        _git(root, *GIT_ID, "commit", "-q", "-m", message)


def blamed_packages(log: str) -> list[str]:
    errors = "\n".join(l for l in log.splitlines() if "npm error" in l or "npm ERR" in l)
    out = []
    for rx in NPM_BLAME:
        for name in rx.findall(errors):
            if name not in out:
                out.append(name)
    return out


def _culprit(pkg: list, log: str = "") -> tuple[dict, dict]:
    """The fix npm's error names (EOVERRIDE, ERESOLVE, ETARGET); otherwise the latest fix with a major
    version jump; otherwise the latest fix."""
    for name in blamed_packages(log):
        named = [(c, v) for c, v in pkg if any(ch.get("package") == name for ch in v.get("changes") or [])
                 or c.get("package") == name]
        if named:
            return named[-1]
    major = [(c, v) for c, v in pkg if any(ch.get("jump") == "major" for ch in v.get("changes") or [])]
    return (major or pkg)[-1]


def _rollback(scan_id: str, root: Path, card: dict, val: dict, why: str, log: str, rec: dict, step: Step) -> None:
    _undo(root, val)
    _commit_tracked(root, f"Guardian: roll back {card['title']}")
    db.save_validation(scan_id, card["id"], {**val, "status": "rolled_back", "reason": why, "rollback_log": log})
    rec["rollbacks"].append({"fix": card["title"], "why": why})
    step(f"rollback_{len(rec['rollbacks'])}", "done", f"Rolled back '{card['title']}': {why}")


def _build(scan_id: str, rec: dict, step: Step) -> None:
    scan = db.get(scan_id)
    res = scan["results"]
    cards = res["remediate"]["cards"]
    root = ensure_copy(scan_id)
    remove_stray_venvs(root)
    art = db.DATA / "scans" / scan_id / "fixed"
    art.mkdir(parents=True, exist_ok=True)
    stop_app(scan_id)
    applied = _applied(scan_id, cards)
    if not applied:
        rec.update(status="error", reason="No approved fix has been applied yet.")
        return
    step("fixes", "done", f"{len(applied)} approved fixes are applied in the fixed copy (branch fix/guardian)")

    build_res = {"status": "not_applicable", "detail": "Only configuration changes: no package build to run"}
    projects = ["."]
    for attempt in range(MAX_ROLLBACKS + 1):
        applied = _applied(scan_id, cards)
        pkg = [(c, v) for c, v in applied if v.get("kind") == "package"]
        if not detect_app(root)["runtime"] and not pkg:
            break  # no Node or Python project at the root and no package fix: nothing to build or run
        # always build and run the app, even with only config fixes left, to show it still works
        projects = sorted({p for _, v in pkg for p in v.get("projects") or ["."]}) or ["."]
        updates = [(proj, name) for _, v in pkg for proj, name in v.get("updates") or []]
        ok, out = True, ""
        for project in projects:
            ok_p, out_p = relock(root / project, [n for p, n in updates if p == project])
            ok, out = ok and ok_p, out + out_p
        (art / "relock.log").write_text(out, encoding="utf-8")
        if not ok:
            if not pkg or attempt == MAX_ROLLBACKS:
                step("relock", "failed", "The dependency tree could not be resolved (npm/uv): " +
                     (", ".join(blamed_packages(out)) or "see the log"), log="relock.log")
                rec.update(status="failed", reason="The dependency tree could not be resolved, even without the package "
                                                   "fixes (see relock.log).")
                return
            if attempt == MAX_ROLLBACKS - 1:  # last resort: undo every package fix so the app runs again
                for c, v in reversed(pkg):
                    _rollback(scan_id, root, c, v, "the package fixes could not be resolved together; all package "
                              "fixes were rolled back so the app runs", out[-4000:], rec, step)
                continue
            c, v = _culprit(pkg, out)
            blamed = blamed_packages(out)
            _rollback(scan_id, root, c, v, "the dependency tree could not be resolved with this fix"
                      + (f" (npm named {', '.join(blamed[:3])})" if blamed else ""), out[-4000:], rec, step)
            continue
        _commit_tracked(root, "Guardian: regenerate lockfiles",
                        [f"{p}/package-lock.json".lstrip("./") or "package-lock.json" for p in projects
                         if (root / p / "package-lock.json").is_file()])
        step("relock", "done", "Dependency tree resolves with all applied fixes", log="relock.log")
        build_res = build_all(root, projects, art)
        broke = build_res["status"] == "failed" and build_res.get("phase") in ("install", "build")
        broke = broke or (build_res.get("smoke") or {}).get("status") == "failed"
        if not broke or not pkg:
            break
        if attempt == MAX_ROLLBACKS - 1:  # last resort: undo every package fix so the app runs again
            for c, v in reversed(pkg):
                _rollback(scan_id, root, c, v, "the app still did not build with the package fixes together; "
                          "all package fixes were rolled back so the app runs", "", rec, step)
            continue
        log_text = (art / build_res["log"]).read_text(encoding="utf-8")[-4000:] if build_res.get("log") else ""
        if not blamed_packages(log_text):  # nothing names a fixed package: does the original app break too?
            original = original_build(root, build_res.get("project", projects[0]), art)
            same = (original["status"] == "failed" and original.get("phase") == build_res.get("phase")) or \
                (build_res.get("phase") is None and (original.get("smoke") or {}).get("status") == "failed")
            step("original_check", "done", "The original app, without any fix, " +
                 ("fails the same way: the fixes are kept" if same else f"passes ({original['detail']})"),
                 log=original.get("log"))
            if same:
                build_res = {**build_res, "original_fails": True,
                             "detail": f"{build_res['detail']}; the original app fails the same way without any fix, "
                                       "so this is a problem in the app itself, not caused by the fixes"}
                break
        c, v = _culprit(pkg, log_text)
        _rollback(scan_id, root, c, v, "the build or the app broke with this fix", log_text, rec, step)
    step("build_test", build_res["status"], build_res["detail"], mode=build_res.get("mode"), log=build_res.get("log"))
    smoke = build_res.get("smoke") or {}
    if smoke.get("status") in ("passed", "failed", "env_error"):
        step("app_smoke_test", smoke["status"], smoke["detail"], log=build_res.get("log"))

    # verify: rescan the fixed copy and compare with the original scan
    after = rescan(scan, root, art)
    applied = _applied(scan_id, cards)
    approved = {cid for cid, d in db.decisions(scan_id).items() if d["decision"] == "approved"}
    vals = db.validations(scan_id)
    not_applied = [(c, vals.get(c["id"], {}).get("reason", "")) for c in cards
                   if c["id"] in approved and vals.get(c["id"], {}).get("status") != "applied"]
    remaining = explain_remaining(scan, after, approved, [c for c, _ in applied], not_applied)
    before = res["vulnerability"]["findings"]
    after_keys = {(v["name"], v["version"], v["advisory_id"]) for v in after["vulnerabilities"]}
    removed = [{"package": f"{v['name']}@{v['version']}", "id": v["advisory_id"], "severity": v["severity"]}
               for v in before if (v["name"], v["version"], v["advisory_id"]) not in after_keys]
    sev = lambda vs: {s: sum(v["severity"] == s for v in vs) for s in ("critical", "high", "medium", "low", "unrated")}
    b_comp = {(c["name"], c["version"]) for c in res["discovery"]["components"]}
    a_comp = {(c["name"], c["version"]) for c in after["components"]}
    b_sus = {f["id"] for f in res["change_detection"]["findings"]}
    for c, v in applied:  # per-card result of the final build
        still = any(x["advisory_id"] in c["advisories_removed"] for x in after["vulnerabilities"]
                    if (x["name"], x["version"]) in {(p["package"], p["version"]) for p in c.get("packages") or []})
        db.save_validation(scan_id, c["id"], {**v, "verified": not still,
                                              "status": "applied" if not still else "applied_still_present"})
    rec.update(
        comparison={
            "advisories_before": len(before), "advisories_after": len(after["vulnerabilities"]),
            "severity_before": sev(before), "severity_after": sev(after["vulnerabilities"]),
            "risk_bands_before": res.get("prioritize", {}).get("counts"), "risk_bands_after": after["risk_counts"],
            "suspicious_before": len(b_sus), "suspicious_after": len(after["suspicious"]),
            "packages_before": len(b_comp), "packages_after": len(a_comp),
            "sbom_diff": {"added": sorted(f"{n}@{v}" for n, v in a_comp - b_comp)[:300],
                          "removed": sorted(f"{n}@{v}" for n, v in b_comp - a_comp)[:300]},
            "removed": removed, "remaining": remaining,
            "new_high_risk": [f"{x['package']} {x['id']}" for x in remaining
                              if x["reason"].startswith("new") and x["severity"] in ("critical", "high")]},
        build=build_res, fixes_applied=[c["title"] for c, _ in applied],
        fixes_not_applied=[{"fix": c["title"], "why": why} for c, why in not_applied], outdated=False)
    step("rescan", "done", f"Advisories {len(before)} -> {len(after['vulnerabilities'])}; "
                           f"suspicious findings {len(b_sus)} -> {len(after['suspicious'])}")
    (art / "fixed.patch").write_text(_git(root, "diff", "guardian-original", "HEAD", "--", ".", ":(exclude)**/node_modules/**"),
                                     encoding="utf-8")
    rec["patch"] = "fixed/fixed.patch"

    # run the fixed app for the person to open
    if build_res.get("mode") == "docker sandbox" and smoke.get("status") == "passed":
        run = start_app(scan_id, root / build_res.get("project", projects[0]))
        rec["app"] = run
        step("run_app", "done" if run["running"] else "failed", run["detail"])
    elif str(build_res.get("mode")).startswith("local") and smoke.get("status") == "passed":  # still running
        url = smoke.get("url") or f"http://localhost:{APP_PORT}/"
        rec["app"] = {"running": True, "url": url, "http_status": smoke.get("http_status"), "local": True,
                      "detail": f"The fixed app is running on this machine at {url} ({smoke.get('command')})"}
        step("run_app", "done", rec["app"]["detail"])
    smoke_ok = smoke.get("status") == "passed"
    if build_res.get("original_fails") and not smoke_ok:
        rec.update(status="original_fails", reason=f"{build_res['detail'].capitalize()}. See build-test-original.log.")
    elif build_res["status"] == "failed" and not smoke_ok:
        rec.update(status="failed", reason=f"The fixed app did not build or start: {build_res['detail']}")
    elif smoke_ok:
        rec.update(status="running_ok", reason=f"The fixed app builds and runs (GET / -> HTTP {smoke.get('http_status')}). "
                                               f"Advisories {len(before)} -> {len(after['vulnerabilities'])}.")
    else:
        rec.update(status="built", reason=f"{build_res['detail']}. Advisories {len(before)} -> {len(after['vulnerabilities'])}.")


def original_build(root: Path, project: str, art: Path) -> dict:
    """Build the unfixed app (tag guardian-original) the same way, in a throwaway git worktree."""
    tmp = root.parent / "original-check"
    _rmtree(tmp)
    try:
        _git(root, "worktree", "prune")
        _git(root, "worktree", "add", "--detach", "-f", str(tmp), "guardian-original")
        return build_and_test(tmp / project, art, "build-test-original.log")
    finally:
        stop_local(str(tmp.resolve()))
        try:
            _git(root, "worktree", "remove", "--force", str(tmp))
        except RuntimeError:
            _rmtree(tmp)


def build_all(root: Path, projects: list[str], art: Path) -> dict:
    """Monorepo: build every changed project (own log each). Report the first one that broke, else the
    primary one: the first whose app starts (that is the one run for the person to open)."""
    results = []
    for i, p in enumerate(projects):
        r = build_and_test(root / p, art, "build-test.log" if i == 0 else f"build-test-{i}.log")
        r["project"] = p
        results.append(r)
        if (r["status"] == "failed" and r.get("phase") in ("install", "build")) or \
                (r.get("smoke") or {}).get("status") == "failed":
            return {**r, "detail": f"{p}: {r['detail']}" if len(projects) > 1 else r["detail"]}
    primary = next((r for r in results if (r.get("smoke") or {}).get("status") == "passed"), results[0])
    if len(results) > 1:
        primary = {**primary, "detail": "; ".join(f"{r['project']}: {r['detail']}" for r in results)}
    return primary


def container_name(scan_id: str) -> str:
    return f"guardian-app-{scan_id}"


def start_app(scan_id: str, project: Path) -> dict:
    """Start the fixed app in Docker with its port published on the host, and wait for GET / to answer."""
    import urllib.request
    stop_app(scan_id)
    plan = detect_app(project)
    if not plan.get("start"):
        return {"running": False, "detail": plan.get("why") or "No start command"}
    env = [x for e in [f"PORT={plan['port']}", *plan["env"]] for x in ("-e", e)]
    cmd = [DOCKER, "run", "-d", "--name", container_name(scan_id), "--cpus", "2", "--memory", "4g",
           "-p", f"{APP_PORT}:{plan['port']}", *env,
           "-v", f"{project.resolve()}:/app", "-w", "/app", plan["image"], "sh", "-c", plan["start"]]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    if out.returncode:
        return {"running": False, "detail": f"docker run failed: {out.stderr.strip()[-300:]}"}
    url = f"http://localhost:{APP_PORT}/"
    for _ in range(90):
        time.sleep(2)
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return {"running": True, "url": url, "http_status": r.status, "container": container_name(scan_id),
                        "detail": f"The fixed app is running at {url} (HTTP {r.status})"}
        except Exception:
            continue
    logs = subprocess.run([DOCKER, "logs", "--tail", "30", container_name(scan_id)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout
    return {"running": False, "url": url, "detail": "The app container started but did not answer in 3 minutes", "log": logs}


def stop_app(scan_id: str) -> bool:
    if stop_local(str(workdir(scan_id).resolve())):
        return True
    if runner_kind() != "docker" or not DOCKER or not docker_ready():
        return False
    out = subprocess.run([DOCKER, "rm", "-f", container_name(scan_id)], capture_output=True, text=True, timeout=60)
    return out.returncode == 0


def app_status(scan_id: str) -> dict:
    prefix = str(workdir(scan_id).resolve())
    for key, p in LOCAL_APPS.items():
        if key.startswith(prefix) and p.poll() is None:
            rec = db.validations(scan_id).get(FIXED) or {}
            return {"running": True, "url": (rec.get("app") or {}).get("url") or f"http://localhost:{APP_PORT}/"}
    if runner_kind() != "docker" or not DOCKER:
        return {"running": False}
    out = subprocess.run([DOCKER, "inspect", "-f", "{{.State.Running}}", container_name(scan_id)],
                         capture_output=True, text=True, timeout=20)
    running = out.returncode == 0 and out.stdout.strip() == "true"
    return {"running": running, "url": f"http://localhost:{APP_PORT}/" if running else None}
