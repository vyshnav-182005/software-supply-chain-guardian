"""Agent 14 · Report: "Show the whole story".

Built on request from the stored scan, the approval decisions and the validation results, so it
always reflects the latest decisions:
  - before vs after: SBOM diff and risk diff for every validated fix
  - remaining risk: still open, rejected, accepted (low band or not reachable), awaiting a decision
  - audit trail per fix card: finding -> evidence -> fix -> decision (who, when) -> build/test -> rescan -> result
  - AI summary at the top, written only from the verified numbers; the Validator rejects any number
    or advisory id that is not in those numbers
  - export as Markdown or JSON
"""
import hashlib
import json
import re
import time

from . import db, llm

SYSTEM = """Write a short executive summary (4-6 sentences, plain English) of a software supply-chain
review, using ONLY the facts in the JSON given. Every number you write must appear in the facts.
Do not invent packages, advisory IDs or outcomes. Reply as JSON: {"summary": "..."}"""


def build(scan_id: str) -> dict:
    scan = db.get(scan_id)
    res = scan["results"]
    decisions, validations = db.decisions(scan_id), db.validations(scan_id)
    combined = validations.pop("fixed", None)  # the fixed copy: every applied fix built, verified and run
    risks = res.get("prioritize", {}).get("risks", [])
    cards = res.get("remediate", {}).get("cards", [])
    risk_by_id = {r["id"]: r for r in risks}

    trail, resolved = [], set()
    for c in cards:
        d, v = decisions.get(c["id"]), validations.get(c["id"])
        r = risk_by_id.get(c["risk_id"], {})
        if v and v.get("status") == "verified":
            resolved |= {f"{p['package']}@{p['version']}" if p.get("version") else p["package"]
                         for p in c.get("packages") or []}
        trail.append({
            "card_id": c["id"], "fix": c["title"], "action": c["action"],
            "finding": {"package": f"{r.get('package')}@{r.get('version')}" if r.get("version") else r.get("package"),
                        "band": r.get("band"), "score": r.get("final_score"), "formula": r.get("formula"),
                        "advisories": [a["id"] for a in r.get("advisories", [])], "labels": r.get("labels", [])},
            "evidence": {"path": r.get("path"), "reachability": r.get("reachability"),
                         "investigation": (r.get("investigation") or {}).get("verdict")},
            "decision": {"decision": d["decision"], "by": d["decided_by"], "at": d["decided_at"]} if d else None,
            "validation": {"status": v.get("status"), "reason": v.get("reason"), "branch": v.get("branch"),
                           "build": (v.get("build") or {}).get("status"), "build_mode": (v.get("build") or {}).get("mode"),
                           "rescan": (v.get("comparison") or {}).get("summary"),
                           "sbom_diff": (v.get("comparison") or {}).get("sbom_diff"),
                           "new_advisories": (v.get("comparison") or {}).get("new_advisories"),
                           "risk_after": (v.get("after") or {}).get("risk_counts")} if v else None,
            "score_before": c["score_before"], "score_after": c["score_after"] if v and v.get("status") == "verified" else None,
        })

    remaining = {"open": [], "rejected": [], "accepted": [], "awaiting_decision": [], "resolved": []}
    card_of = {c["risk_id"]: c for c in cards}
    for r in risks:
        key = f"{r['package']}@{r['version']}" if r.get("version") else r["package"]
        row = {"package": key, "band": r["band"], "score": r["final_score"]}
        c = card_of.get(r["id"])
        if key in resolved:
            remaining["resolved"].append(row)
        elif c and decisions.get(c["id"], {}).get("decision") == "rejected":
            remaining["rejected"].append(row)
        elif c and c["id"] not in decisions:
            remaining["awaiting_decision"].append(row)
        elif r["band"] == "low" or r.get("reachability") == "not_reachable":
            remaining["accepted"].append(row)
        else:
            remaining["open"].append(row)

    bands = ("critical", "high", "medium", "low")
    before = {b: sum(r["band"] == b for r in risks) for b in bands}
    after = {b: sum(x["band"] == b for k in ("open", "rejected", "accepted", "awaiting_decision") for x in remaining[k])
             for b in bands}
    vstat = [v.get("status") for v in validations.values()]
    facts = {
        "repository": scan["repo_url"].removeprefix("https://github.com/"), "commit": (scan["commit_sha"] or "")[:12],
        "components": res.get("discovery", {}).get("stats", {}).get("components"),
        "vulnerable_or_risky_packages_ranked": len(risks), "risk_bands_before": before, "risk_bands_after": after,
        "fix_cards": len(cards), "approved": sum(d["decision"] == "approved" for d in decisions.values()),
        "rejected": sum(d["decision"] == "rejected" for d in decisions.values()),
        "awaiting_decision": len(remaining["awaiting_decision"]),
        "validated": {s: vstat.count(s) for s in ("verified", "fixed_untested", "fixed_tests_failed", "not_fixed", "manual", "error")},
        "packages_resolved_by_verified_fixes": len(remaining["resolved"]),
    }
    if combined and combined.get("comparison"):
        cmp_, smoke = combined["comparison"], (combined.get("build") or {}).get("smoke") or {}
        reasons: dict = {}
        for x in cmp_["remaining"]:
            reasons[x["reason"]] = reasons.get(x["reason"], 0) + 1
        facts["combined"] = {"status": combined["status"], "fixes_applied": len(combined.get("fixes_applied", [])),
                             "fixes_not_applied": len(combined.get("fixes_not_applied", [])),
                             "fixes_rolled_back": len(combined.get("rollbacks", [])),
                             "advisories_removed": len(cmp_.get("removed", [])),
                             "app_url": (combined.get("app") or {}).get("url"),
                             "advisories_before": cmp_["advisories_before"], "advisories_after": cmp_["advisories_after"],
                             "severity_before": cmp_["severity_before"], "severity_after": cmp_["severity_after"],
                             "app_runs": smoke.get("status") == "passed", "app_http_status": smoke.get("http_status"),
                             "build": (combined.get("build") or {}).get("status"), "remaining_by_reason": reasons}
    incompatible = [{"fix": c["title"], "why": (c.get("compat") or {}).get("reason") or validations.get(c["id"], {}).get("reason")}
                    for c in cards if (c.get("compat") or {}).get("ok") is False
                    or validations.get(c["id"], {}).get("status") == "conflicts"]
    facts["skipped_incompatible"] = len(incompatible)
    report = {"facts": facts, "remaining": remaining, "audit_trail": trail, "combined": combined,
              "skipped_incompatible": incompatible,
              "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    report["summary"] = summarize(facts)
    return report


def summarize(facts: dict) -> dict:
    allowed = {str(x) for x in re.findall(r"\d+(?:\.\d+)?", json.dumps(facts))}
    subject = hashlib.sha1(json.dumps(facts, sort_keys=True).encode()).hexdigest()[:16]

    def validate(a):
        text = a.get("summary")
        if not isinstance(text, str) or not text.strip():
            return ["'summary' must be a short paragraph"]
        bad = sorted({n for n in re.findall(r"\d+(?:\.\d+)?", text) if n not in allowed})
        p = [f"these numbers are not in the facts: {bad}"] if bad else []
        return p + llm.check_ids(text, set())
    ai = llm.ask_batch("report", SYSTEM, [{"subject": subject, "user": json.dumps(facts, indent=1), "validate": validate}])[subject]
    if ai.get("ok"):
        return {"text": ai["answer"]["summary"], "source": "AI (numbers checked against the facts)"}
    f = facts
    text = (f"{f['repository']} at {f['commit']}: {f['vulnerable_or_risky_packages_ranked']} packages or findings were ranked "
            f"({f['risk_bands_before']['critical']} critical, {f['risk_bands_before']['high']} high). "
            f"{f['approved']} of {f['fix_cards']} fixes were approved and {f['rejected']} rejected; "
            f"{f['validated']['verified']} fixes were verified by rebuild and rescan. "
            f"{f['packages_resolved_by_verified_fixes']} packages are resolved; {f['awaiting_decision']} still await a decision.")
    return {"text": text, "source": "rule"}


def markdown(rep: dict) -> str:
    f = rep["facts"]
    out = [f"# Supply-chain report: {f['repository']} @ {f['commit']}", "", f"_{rep['generated_at']}_", "",
           "## Summary", "", rep["summary"]["text"], "", "## Before vs after", "",
           "| Band | Before | After |", "|---|---|---|"]
    out += [f"| {b} | {f['risk_bands_before'][b]} | {f['risk_bands_after'][b]} |" for b in f["risk_bands_before"]]
    out += ["", f"Fix cards {f['fix_cards']}: approved {f['approved']}, rejected {f['rejected']}, "
                f"awaiting {f['awaiting_decision']}. Validation: " + ", ".join(f"{k} {v}" for k, v in f["validated"].items()), "",
            "## Remaining risk", ""]
    for k, rows in rep["remaining"].items():
        out.append(f"- **{k.replace('_', ' ')}** ({len(rows)}): " + ", ".join(f"{r['package']} ({r['band']} {r['score']})" for r in rows[:30]))
    out += ["", "## Audit trail", ""]
    for t in rep["audit_trail"]:
        d, v = t["decision"], t["validation"]
        out += [f"### {t['fix']}", f"- Finding: {t['finding']['package']} - {t['finding']['band']} {t['finding']['score']} "
                                    f"({t['finding']['formula']})",
                f"- Evidence: path {' -> '.join(t['evidence']['path'] or [])}; reachability {t['evidence']['reachability']}",
                f"- Decision: {d['decision']} by {d['by']} at {d['at']}" if d else "- Decision: awaiting",
                f"- Validation: {v['status']} - {v['reason']} (build/test: {v['build']}, {v['build_mode']}; rescan: {v['rescan']})"
                if v else "- Validation: not run", ""]
    if rep.get("skipped_incompatible"):
        out += ["## Fixes skipped as incompatible", ""]
        out += [f"- {x['fix']}: {x['why']}" for x in rep["skipped_incompatible"]]
        out.append("")
    c = rep.get("combined")
    if c and c.get("comparison"):
        cf = f["combined"]
        out += ["## The fixed application (branch fix/guardian)", "",
                f"- Result: {c['status']} - {c.get('reason', '')}",
                f"- Advisories: {cf['advisories_before']} -> {cf['advisories_after']}",
                f"- App: {'runs, GET / answered HTTP ' + str(cf['app_http_status']) if cf['app_runs'] else 'not confirmed running'}",
                f"- Fixes applied {cf['fixes_applied']}, not applied {cf['fixes_not_applied']}, rolled back {cf['fixes_rolled_back']}",
                "", "Removed advisories: " + ", ".join(f"{x['package']} {x['id']}" for x in c["comparison"].get("removed", [])[:60]),
                "", "| Remaining advisory | Severity | Why it is still there |", "|---|---|---|"]
        out += [f"| {x['package']} {x['id']} | {x['severity']} | {x['reason']} |" for x in c["comparison"]["remaining"]]
    return "\n".join(out)
