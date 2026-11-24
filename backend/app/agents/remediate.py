"""Day 2 · Recommend Fix: "What exactly do we change?"

For each top-ranked risk (critical/high band, at most 15):
  target   = the vulnerable package T; `need` = highest fixed version among its advisories
  control  = the package you actually list in package.json (T itself if direct, else the first
             package on its "introduced via" path)
  1. Upgrade: walk the controlled package's published versions (npm registry) from low to high
     and, emulating npm (highest version satisfying each range), resolve the chain down to T.
     The first version where T resolves to >= need (or is no longer pulled in) is the fix.
  2. Override: if no version of the controlled package brings a safe T, pin T with npm
     "overrides" (npm >= 8.3).
  3. Replace / mitigate: no fixed version of T exists at all.
Recorded per card: advisories and CVEs removed, what remains, version-jump type, rollback,
the package.json change, the resolution chain and registry evidence.

LLM: reads the changelog (GitHub releases between the two versions) plus where the app uses
the package, and explains what may break and why. The Validator checks cited file:line are among
the snippets shown. Without the LLM the card still has the rule-based jump type.
"""
import hashlib
import json
import re
import os
import urllib.parse
import urllib.request
from pathlib import Path

from semantic_version import NpmSpec, Version

from .. import llm  # noqa: F401  (importing llm loads backend/.env)
from .prioritize import band, fetch_json, find_usages

MAX_CARDS = 60
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # optional; read after llm loads backend/.env
REGISTRY = "https://registry.npmjs.org/"

SYSTEM = """You review a proposed npm dependency upgrade for breaking changes. Use ONLY the changelog
excerpt and the application code snippets given (line numbers are shown before each line).
Explain concretely what in THIS application's code could break and why; if the changelog says
nothing relevant, say so and rate the risk low. Never invent advisory IDs or APIs.
Also write "explanation": 2-3 short sentences in plain English for a non-specialist who must click
Approve or Reject: what the security problem is, what this change does, and what might break.
No jargon, no IDs. Reply as JSON:
{"explanation": "plain-English 2-3 sentences", "breaking_risk": "low|medium|high",
 "summary": "2-3 sentences (technical)", "notes": [{"text": "...", "file": "path or null", "line": 1}]}"""

_packuments: dict[str, dict] = {}


def packument(name: str) -> dict:
    if name not in _packuments:
        _packuments[name] = fetch_json(REGISTRY + urllib.parse.quote(name, safe="@"), 60)
    return _packuments[name]


def ver(s: str) -> Version | None:
    try:
        return Version(s)
    except ValueError:
        try:
            return Version.coerce(s)
        except ValueError:
            return None


def stable_versions(name: str) -> list[Version]:
    vs = [v for v in (ver(x) for x in packument(name).get("versions", {})) if v and not v.prerelease]
    return sorted(vs)


def resolve(name: str, spec: str) -> Version | None:
    """npm picks the highest published version matching the range."""
    try:
        return NpmSpec(spec).select(stable_versions(name))
    except ValueError:
        return None


def deps_of(name: str, version: Version) -> dict:
    meta = packument(name)["versions"].get(str(version), {})
    return {**(meta.get("optionalDependencies") or {}), **(meta.get("dependencies") or {})}


def walk_chain(chain: list[str], top_version: Version) -> tuple[Version | None, list] | None:
    """Resolve chain[0]@top_version down to chain[-1]. Returns (T version or None if dropped, steps)."""
    steps, current = [{"package": chain[0], "version": str(top_version)}], top_version
    for parent, child in zip(chain, chain[1:]):
        spec = deps_of(parent, current).get(child)
        if spec is None:
            return None, steps  # child no longer pulled in through this route
        current = resolve(child, spec)
        if current is None:
            return False, steps  # unresolvable: treat as not fixed
        steps.append({"package": child, "version": str(current), "range": spec})
    return current, steps


def jump(a: Version, b: Version) -> str:
    return "major" if b.major != a.major else "minor" if b.minor != a.minor else "patch"


def manifest_spec(root: Path, project_path: str, name: str) -> tuple[str | None, str | None, str]:
    pj = root / project_path / "package.json"
    data = json.loads(pj.read_text(encoding="utf-8")) if pj.exists() else {}
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        if name in (data.get(field) or {}):
            return data[field][name], field, pj.relative_to(root).as_posix()
    return None, None, pj.relative_to(root).as_posix()


_releases: dict[str, list] = {}


def changelog(name: str, frm: Version | None, to: Version | None) -> tuple[str, str]:
    if frm is None or to is None:  # e.g. a lockfile fix whose target is "removed", or an unusual version string
        return "", "no version range to compare"
    repo = (packument(name).get("repository") or {})
    url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
    m = re.search(r"github\.com[/:]([^/]+)/([^/#.]+)", url)
    if not m:
        return "", "no GitHub repository listed on the registry"
    api = f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/releases?per_page=100"
    try:
        if api not in _releases:
            req = urllib.request.Request(api, headers={"User-Agent": "supply-chain-guardian",
                                                       **({"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {})})
            with urllib.request.urlopen(req, timeout=30) as resp:
                _releases[api] = json.load(resp)
        rel = _releases[api]
    except Exception as e:
        hint = "" if GITHUB_TOKEN else "; set GITHUB_TOKEN in backend/.env to raise GitHub's 60 requests/hour limit"
        return "", f"GitHub releases unavailable ({str(e)[:80]}{hint})"
    picked = []
    for r in rel:
        v = ver(re.sub(r"^[^\d]*", "", r.get("tag_name", "")))
        if v and frm < v <= to and r.get("body"):
            picked.append(f"## {r['tag_name']}\n{r['body'].strip()[:1500]}")
    text = "\n\n".join(sorted(picked))[:5000]
    return text, f"https://github.com/{m.group(1)}/{m.group(2)}/releases" if text else "no release notes between these versions"


OSV_QUERY = "https://api.osv.dev/v1/query"
_osv_cache: dict[tuple[str, str], list] = {}
MAX_VETTED = 12  # candidate versions checked against OSV per route


def serious_advisories(name: str, version: str) -> list[str]:
    """High/critical (or malware) advisories OSV lists for name@version. Unknown on network errors -> []."""
    key = (name, version)
    if key not in _osv_cache:
        try:
            req = urllib.request.Request(OSV_QUERY, method="POST", headers={"Content-Type": "application/json",
                                                                           "User-Agent": "supply-chain-guardian"},
                                         data=json.dumps({"package": {"name": name, "ecosystem": "npm"},
                                                          "version": version}).encode())
            with urllib.request.urlopen(req, timeout=30) as resp:
                vulns = json.load(resp).get("vulns", [])
            _osv_cache[key] = [v["id"] for v in vulns if v["id"].startswith("MAL-") or
                               str((v.get("database_specific") or {}).get("severity", "")).upper() in ("HIGH", "CRITICAL")]
        except Exception:
            _osv_cache[key] = []
    return _osv_cache[key]


def routes_to(cid: str, edges: list, comps: dict) -> list[tuple[str, list[str]]]:
    """Every (project, chain of component ids) from a package the project lists itself down to cid."""
    fwd, back = {}, {}
    for e in edges:
        fwd.setdefault(e["source"], []).append(e["target"])
        back.setdefault(e["target"], []).append(e["source"])
    ancestors, todo = {cid}, [cid]
    while todo:
        for p in back.get(todo.pop(), []):
            if p not in ancestors:
                ancestors.add(p)
                todo.append(p)
    out = []
    for proj in sorted(a for a in ancestors if a.startswith("project:")):
        for d in sorted(set(fwd.get(proj, [])) & ancestors):
            prev, queue = {d: None}, [d]  # shortest d -> cid inside the ancestor set
            while queue and cid not in prev:
                n = queue.pop(0)
                for m in fwd.get(n, []):
                    if m in ancestors and m not in prev:
                        prev[m] = n
                        queue.append(m)
            if cid in prev:
                chain, n = [], cid
                while n is not None:
                    chain.append(n)
                    n = prev[n]
                out.append((proj, chain[::-1]))
    return out


def find_safe(chain: list[str], current: Version, need: Version) -> tuple[Version | None, object, list, list]:
    """Lowest version of chain[0] (>= current) whose resolution removes the vulnerable chain[-1] version and
    whose resolved chain has no known high/critical advisory (checked with OSV). Returns
    (version, resolved target or None if dropped, steps, advisories that made earlier candidates unsafe)."""
    rejected, vetted = [], 0
    for v in [v for v in stable_versions(chain[0]) if v >= current][:200]:
        if len(chain) == 1:
            t_new, steps = v, [{"package": chain[0], "version": str(v)}]
            ok = v >= need
        else:
            t_new, steps = walk_chain(chain, v)
            ok = t_new is None or (t_new is not False and t_new >= need)
        if not ok:
            continue
        bad = [f"{s['package']}@{s['version']} {a}" for s in steps for a in serious_advisories(s["package"], s["version"])]
        if not bad:
            return v, t_new, steps, rejected
        rejected.append({"version": str(v), "because": bad[:3]})
        vetted += 1
        if vetted >= MAX_VETTED:
            break
    return None, None, [], rejected


def plan_fix(r: dict, comps: dict, paths: dict, root: Path, edges: list | None = None) -> dict:
    cid = r["component"]
    path = paths.get(cid) or []
    T, current_t = r["package"], ver(r["version"])
    routes = routes_to(cid, edges or [], comps) or \
        [(path[1] if len(path) > 1 else "project:.", path[2:] if len(path) > 2 else [cid])]
    chains = [[comps[i]["name"] for i in ids if i in comps] for _, ids in routes]
    fixes = sorted({ver(a["fix"]) for a in r["advisories"] if a["fix"] and ver(a["fix"])})
    card = {"id": hashlib.sha1(f"fix|{cid}".encode()).hexdigest()[:12], "risk_id": r["id"], "rank": r["rank"],
            "package": T, "version": r["version"], "band": r["band"], "score_before": r["final_score"],
            "chain": chains[0], "routes": [" → ".join(c) for c in chains],
            "project": routes[0][0].removeprefix("project:"),
            "evidence": {"registry": sorted({REGISTRY + n for c in chains for n in c})}}
    if not fixes:
        return {**card, "action": "replace", "title": f"No fixed version of {T} exists: replace or mitigate",
                "advisories_removed": [], "cves_removed": [], "remaining": [a["id"] for a in r["advisories"]],
                "score_after": r["final_score"], "change": None, "rollback": None, "patch": None}
    need = fixes[-1]

    # one safe change per route (a vulnerable version can be pulled in by several of your packages)
    changes, steps_all, t_afters, rejected, missing = [], [], [], [], []
    for (proj, ids), chain in zip(routes, chains):
        project_path = proj.removeprefix("project:")
        D, d_current = chain[0], ver(comps[ids[0]]["version"]) or Version("0.0.0")
        spec_from, field, manifest = manifest_spec(root, project_path, D)
        cand, t_new, steps, rej = find_safe(chain, d_current, need)
        rejected += rej
        if cand is None:
            missing.append(D)
            continue
        steps_all.append(steps)
        t_afters.append(need if len(chain) == 1 else t_new)
        if cand == d_current and len(chain) > 1:  # the range you already have allows the fixed version
            changes.append({"package": T, "from": r["version"], "to": str(t_new) if t_new else "removed",
                            "spec_from": None, "spec_to": None, "field": "lockfile", "via": D,
                            "manifest": manifest.replace("package.json", "package-lock.json"),
                            "jump": jump(current_t, t_new) if current_t and t_new else "n/a"})
        else:
            changes.append({"package": D, "from": str(d_current), "to": str(cand), "spec_from": spec_from,
                            "spec_to": f"^{cand}", "field": field, "manifest": manifest, "jump": jump(d_current, cand)})
    note = (" Skipped versions with known high/critical advisories: "
            + "; ".join(f"{x['version']} ({', '.join(x['because'])})" for x in rejected[:3])) if rejected else ""

    if missing or not changes:
        manifest = changes[0]["manifest"] if changes else manifest_spec(root, routes[0][0].removeprefix("project:"), T)[2]
        manifest = manifest.replace("package-lock.json", "package.json")
        bad = serious_advisories(T, str(need))
        change = {"package": T, "from": r["version"], "to": str(need), "spec_from": None, "spec_to": f"^{need}",
                  "field": "overrides", "manifest": manifest, "jump": jump(current_t, need) if current_t else "unknown"}
        title = (f"Pin {T} to ^{need} with npm overrides (no safe release of {', '.join(missing) or 'its parent'} "
                 f"pulls in a fixed {T})" + (f" - note: {T} {need} itself has {', '.join(bad)}" if bad else ""))
        return finish(card, r, "override", title, [change], need, [], note,
                      f'--- {manifest}\n+++ {manifest}\n+  "overrides": {{\n+    "{T}": "^{need}"\n+  }},',
                      {"version": r["version"], "how": f'Remove the "{T}" entry from "overrides" in {manifest} and reinstall.'})

    parts = [(f"refresh the lockfile so {c['via']} gets {T} {c['to']}" if c["field"] == "lockfile"
              else f"{c['package']} {c['from']} → {c['to']}") for c in changes]
    if len(changes) == 1 and changes[0]["field"] == "lockfile":
        c = changes[0]
        action, title = "relock", f"Refresh the lockfile: {c['via']} already allows {T} {c['to']} (npm update {T})"
    elif len(changes) == 1:
        c = changes[0]
        action = "upgrade" if c["package"] == T else "upgrade-parent"
        title = f"Upgrade {c['package']} {c['from']} → {c['to']}" + ("" if c["package"] == T else
                f" (pulls {T} {'out of the tree' if t_afters[0] is None else t_afters[0]})")
    else:
        action = "upgrade-all"
        title = f"Fix every route to {T} {r['version']} ({len(changes)} changes): " + "; ".join(parts)
    patch = "\n".join(
        f"npm update {T}   # lockfile only, via {c['via']}" if c["field"] == "lockfile" else
        f'--- {c["manifest"]}\n+++ {c["manifest"]}\n   "{c["field"]}": {{\n-    "{c["package"]}": "{c["spec_from"]}",\n+    "{c["package"]}": "{c["spec_to"]}",'
        for c in changes)
    rollback = {"version": ", ".join(f"{c['package']} {c['from']}" for c in changes),
                "how": "Put the previous versions back in package.json (and package-lock.json) from git and reinstall."}
    real = [t for t in t_afters if t is not None]
    t_after = min(real) if real else None
    return finish(card, r, action, title + ("." if not note else ""), changes, t_after,
                  [s for st in steps_all for s in st], note, patch, rollback)


def finish(card, r, action, title, changes, t_after, steps, note, patch, rollback) -> dict:
    removed = [a for a in r["advisories"] if a["fix"] and (t_after is None or (ver(a["fix"]) and ver(a["fix"]) <= t_after))]
    remaining = [a for a in r["advisories"] if a not in removed]
    f = r["factors"]
    after = 0.0 if not remaining else round(min(10, max((a["cvss"] or 5.0) for a in remaining) * f["U"] * f["D"] * f["P"] * f["E"]), 1)
    return {**card, "action": action, "title": title, "change": changes[0], "changes": changes, "patch": patch,
            "rollback": rollback, "resolution": steps, "vetting": note.strip(),
            "target_after": "removed from tree" if t_after is None else str(t_after),
            "advisories_removed": [a["id"] for a in removed], "cves_removed": sorted({c for a in removed for c in a["cves"]}),
            "remaining": [a["id"] for a in remaining], "score_after": after, "band_after": band(after)}


def run(state: dict) -> tuple[dict, dict]:
    comps = {c["id"]: c for c in state["components"]}
    paths, root = state.get("paths", {}), Path(state["workdir"])
    # every band, critical to low, in priority order, so as many advisories as possible can be removed
    top = [r for r in state.get("risks", []) if "known malware" not in r["labels"] and r.get("advisories")][:MAX_CARDS]
    known_ids = {x for v in state.get("vulnerabilities", []) for x in [v["advisory_id"], *v["aliases"]]}
    cards, errors = [], []
    for r in top:
        try:
            card = plan_fix(r, comps, paths, root, state.get("edges", []))
        except Exception as e:  # registry down etc.: keep going, say which card is missing
            errors.append({"package": r["package"], "error": f"{type(e).__name__}: {str(e)[:200]}"})
            continue
        # each vulnerable package keeps its own score from Prioritize, also after cards are merged
        card["packages"] = [{"package": card["package"], "version": card["version"], "band": card["band"],
                             "score_before": card["score_before"], "score_after": card["score_after"]}]
        cards.append(card)
    cards = merge_same_change(cards)  # merge first, so the AI reviews each change once
    for card in cards:  # the package being changed first, then the ones it pulls in
        changed = (card.get("change") or {}).get("package")
        card["packages"].sort(key=lambda p: (p["package"] != changed, -p["score_before"]))
    requests = []
    for card in cards:
        ch = card.get("change")
        if ch and card["action"] != "replace":
            try:  # one odd version or a registry hiccup must not fail the whole scan
                notes, source = changelog(ch["package"], ver(str(ch["from"])), ver(str(ch["to"])))
            except Exception as e:
                notes, source = "", f"changelog unavailable ({type(e).__name__})"
            card["evidence"]["changelog"] = source
            snippets = find_usages(root, [ch["package"]])
            card["usage_snippets"] = snippets
            requests.append(review(card, notes, snippets, root, known_ids))
    answers = llm.ask_batch("remediate", SYSTEM, requests)  # 5 fix cards per API call
    for card in cards:
        ch = card.get("change")
        subject = f"{ch['package']}@{ch['from']}->{ch['to']}" if ch else None
        card["ai"] = answers.get(subject) or {"ok": False, "reason": "no change to review"}
        card["plain"] = plain_explanation(card)
        card["compatibility"] = {"jump": (ch or {}).get("jump"),
                                 "breaking_risk": card["ai"]["answer"]["breaking_risk"] if card["ai"].get("ok") else None}
    # supply-chain risks without a CVE: nothing to upgrade to, so freeze the reviewed version and escalate
    for r in state.get("risks", []):
        if "repo config" in r["labels"]:
            cards.append(config_card(r, state))
        elif "supply-chain risk" in r["labels"] and "known malware" not in r["labels"]:
            cards.append(pin_card(r, paths, root))
    # malware is never "upgraded": it gets its own card
    for r in state.get("risks", []):
        if "known malware" in r["labels"]:
            cards.insert(0, {"id": hashlib.sha1(f"fix|{r['component']}".encode()).hexdigest()[:12], "risk_id": r["id"],
                             "rank": r["rank"], "package": r["package"], "version": r["version"], "band": "critical",
                             "action": "remove", "title": f"Remove {r['package']}@{r['version']} (known malware)",
                             "score_before": 10.0, "score_after": 0.0, "advisories_removed": [a["id"] for a in r["advisories"]],
                             "packages": [{"package": r["package"], "version": r["version"], "band": "critical",
                                           "score_before": 10.0, "score_after": 0.0}],
                             "cves_removed": [], "remaining": [], "change": None, "patch": None,
                             "rollback": None, "ai": {"ok": False, "reason": "no AI for malware removal"},
                             "compatibility": {"jump": None, "breaking_risk": None}, "evidence": {},
                             "plain": {"source": "rule", "text": f"{r['package']} {r['version']} is known malware. "
                                       "Removing it stops it from running on your machines; anything that "
                                       "depends on it must be replaced."}})
    conflicts = check_compatibility(cards, root)
    public = {
        "cards": cards, "errors": errors, "llm": {**llm.status(), "answered": sum(bool(c["ai"].get("ok")) for c in cards)},
        "conflicts": conflicts,
        "_status": "partial" if errors else "done",
        "_summary": f"{len(cards)} fix cards for {len(top)} risks"
                    + (f"; {conflicts} conflict with the project's dependencies" if conflicts else "")
                    + (f"; {len(errors)} could not be planned" if errors else ""),
    }
    return {"fixes": cards}, public


CONFIG_FIX = {
    "unpinned-action": ("Pin the action to a full commit SHA",
                        "This workflow step uses another author's GitHub Action through a tag that its owner can move "
                        "to new code at any time, and that code would run in your CI with your secrets. Pinning it to "
                        "the exact commit (the SHA the tag points to today) means it can only change when you change it."),
    "base-image": ("Pin the base image by digest",
                   "The container is built on an image reference that can point to different contents over time. "
                   "Adding the image's @sha256 digest locks the exact image you tested; update it on purpose when needed."),
    "build-install": ("Install from the lockfile, never run downloaded scripts",
                      "The image build installs or runs code that is not locked to known versions. Use 'npm ci' with a "
                      "committed package-lock.json (and --ignore-scripts where possible), and download files with a "
                      "checksum check instead of piping them into a shell."),
    "workflow-risk": ("Restrict the workflow trigger and permissions",
                      "This workflow can give untrusted input, for example from a fork's pull request, access to your "
                      "repository's token or secrets. Use the 'pull_request' trigger (or never check out the PR's code), "
                      "set the smallest 'permissions:' needed, and pass event text through environment variables."),
}


def config_card(r: dict, state: dict) -> dict:
    inv = next((i for i in state.get("investigations", []) if i["component"] == r["component"]), {})
    rule = inv.get("rule", "workflow-risk")
    title, why = CONFIG_FIX.get(rule, CONFIG_FIX["workflow-risk"])
    file, line, text = inv.get("file", ""), inv.get("line"), inv.get("text", "")
    suggestion = {
        "unpinned-action": f"-  {text}\n+  {text.split('@')[0]}@<40-character commit SHA>  # {text.split('@')[-1]}",
        "base-image": f"-{text}\n+{text.split(' AS ')[0]}@sha256:<digest of this image>",
        "build-install": f"-{text}\n+RUN npm ci --omit=dev   # with package-lock.json committed",
        "workflow-risk": f"-{text}\n+# use 'pull_request', least-privilege 'permissions:', and env: for event text",
    }.get(rule, "")
    score = r["final_score"]
    return {
        "id": hashlib.sha1(f"fix|{r['component']}".encode()).hexdigest()[:12], "risk_id": r["id"], "rank": r["rank"],
        "package": r["package"], "version": "", "band": r["band"], "action": "config",
        "title": f"{title}: {file}:{line}", "change": None,
        "patch": f"--- {file}\n+++ {file}\n@@ line {line} @@\n{suggestion}",
        "rollback": {"version": "", "how": f"Revert the change to {file}."},
        "advisories_removed": [], "cves_removed": [], "remaining": [], "score_before": score, "score_after": 0.0,
        "band_after": "low", "evidence": {"investigation": inv.get("verdict"), "file": file, "line": line},
        "ai": {"ok": False, "reason": "configuration change: no package upgrade to review"},
        "compatibility": {"jump": "none", "breaking_risk": "low"},
        "packages": [{"package": r["package"], "version": "", "band": r["band"], "score_before": score, "score_after": 0.0}],
        "plain": {"source": "rule", "text": why},
    }


def pin_card(r: dict, paths: dict, root: Path) -> dict:
    path = paths.get(r["component"]) or []
    project_path = path[1].removeprefix("project:") if len(path) > 1 else "."
    manifest = (root / project_path / "package.json").relative_to(root).as_posix()
    inv = r.get("investigation") or {}
    score = r["final_score"]
    return {
        "id": hashlib.sha1(f"fix|{r['component']}".encode()).hexdigest()[:12], "risk_id": r["id"], "rank": r["rank"],
        "package": r["package"], "version": r["version"], "band": r["band"], "action": "pin",
        "title": f"Pin {r['package']} to the reviewed version {r['version']} and escalate for security review",
        "change": {"package": r["package"], "from": r["version"], "to": r["version"], "spec_from": None,
                   "spec_to": r["version"], "field": "overrides", "manifest": manifest, "jump": "none"},
        "patch": f'--- {manifest}\n+++ {manifest}\n+  "overrides": {{\n+    "{r["package"]}": "{r["version"]}"\n+  }},',
        "rollback": {"version": r["version"], "how": f'Remove the "{r["package"]}" entry from "overrides" in {manifest}.'},
        "advisories_removed": [], "cves_removed": [], "remaining": [], "score_before": score, "score_after": score,
        "band_after": r["band"], "evidence": {"investigation": inv.get("verdict")},
        "ai": {"ok": False, "reason": "no upgrade to review: supply-chain risk without a CVE"},
        "compatibility": {"jump": "none", "breaking_risk": "low"},
        "packages": [{"package": r["package"], "version": r["version"], "band": r["band"],
                      "score_before": score, "score_after": score}],
        "plain": {"source": "rule", "text":
                  f"The Investigation agent found that {r['package']} {r['version']} does risky things when it is "
                  "installed (see the Investigation tab for the exact lines). There is no known vulnerability to "
                  "patch, so this pins it to the exact version that was checked, so a new, unreviewed release "
                  "cannot slip in, and flags it for a security review. The risk is frozen, not removed."},
    }


DRY_RUN = os.environ.get("GUARDIAN_FIX_DRYRUN", "on").lower() not in ("0", "off", "false", "no")


def check_compatibility(cards: list, root: Path) -> int:
    """npm dry run of every package fix on its own against the scanned project (4 at a time). A card npm
    cannot install is marked with npm's reason, and Approve is blocked for it."""
    from concurrent.futures import ThreadPoolExecutor

    from ..validate import dry_run
    todo = [c for c in cards if c["action"] in ("upgrade", "upgrade-parent", "upgrade-all", "relock", "override", "pin")]
    if not DRY_RUN or not todo:
        return 0
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda c: dry_run(c, root), todo))
    for c, r in zip(todo, results):
        c["compat"] = {"ok": r["ok"], "reason": r["reason"], "blamed": r["blamed"]}
        if not r["ok"]:
            c["plain"] = {"source": "rule", "text": "npm cannot install this fix with the project's other dependencies, "
                                                    f"so it cannot be approved: {r['reason']}"}
    return sum(not r["ok"] for r in results)


def plain_explanation(card: dict) -> dict:
    """Simple words for the approver: the AI's explanation if it passed the Validator, else a rule sentence."""
    if card["ai"].get("ok") and card["ai"]["answer"].get("explanation"):
        return {"text": card["ai"]["answer"]["explanation"], "source": "AI"}
    n, ch = len(card["advisories_removed"]), card.get("change") or {}
    problem = (f"{card['package']} {card['version']} has {n} known security problem{'s' if n != 1 else ''}."
               if n else f"{card['package']} {card['version']} has known security problems.")
    what = {"upgrade": f"This updates {ch.get('package')} from {ch.get('from')} to {ch.get('to')}.",
            "upgrade-parent": f"This updates {ch.get('package')} from {ch.get('from')} to {ch.get('to')}, "
                              f"which brings in a safe version of {card['package']}.",
            "relock": f"This only refreshes the lockfile so {card['package']} moves to {ch.get('to')}; "
                      "package.json does not change.",
            "override": f"This forces {card['package']} to {ch.get('to')} with an npm override.",
            "replace": "No safe version has been published, so the package has to be replaced or its use limited."
            }.get(card["action"], "")
    risk = {"major": "It is a major version change, so some code may need updating; test before release.",
            "minor": "It is a minor version change and should not break anything, but run the tests.",
            "patch": "It is a small patch change and is very unlikely to break anything."}.get(ch.get("jump"), "")
    return {"text": " ".join(x for x in (problem, what, risk) if x), "source": "rule"}


def merge_same_change(cards: list) -> list:
    """One card per change: several vulnerable versions fixed by the same change (e.g. three minimist
    versions), or several upgrades of the same package you control (kept at the highest target,
    which also contains the lower fixes), become one card."""
    out, seen = [], {}
    for c in cards:
        ch = c.get("change")
        upgrade = c["action"] in ("upgrade", "upgrade-parent")
        key = ("upgrade", ch["package"]) if ch and upgrade else (c["action"], ch["package"], ch["to"]) if ch else None
        if key and key in seen:
            first = seen[key]
            if upgrade and (ver(str(ch["to"])) or Version("0.0.0")) > (ver(str(first["change"]["to"])) or Version("0.0.0")):
                for k in ("change", "changes", "routes", "vetting", "patch", "resolution", "target_after", "title",
                          "evidence", "usage_snippets", "ai",
                          "compatibility", "plain"):
                    if k in c:
                        first[k] = c[k]
            first["packages"] = first["packages"] + c["packages"]
            first["score_before"] = max(p["score_before"] for p in first["packages"])  # card = its worst package
            first["score_after"] = max(p["score_after"] for p in first["packages"])
            first.setdefault("also_fixes", []).append(f"{c['package']}@{c['version']}")
            first["advisories_removed"] = sorted(set(first["advisories_removed"]) | set(c["advisories_removed"]))
            first["cves_removed"] = sorted(set(first["cves_removed"]) | set(c["cves_removed"]))
            first["remaining"] = sorted(set(first["remaining"]) | set(c["remaining"]))
            continue
        if key:
            seen[key] = c
        out.append(c)
    return out


def review(card: dict, notes: str, snippets: list, root: Path, known_ids: set) -> dict:
    ch = card["change"]
    shown = "\n\n".join(f"FILE {s['file']}\n{llm.numbered(s['lines'], s['start'])}" for s in snippets) \
        or "The application source does not import this package directly."
    user = (f"Proposed change: {ch['package']} {ch['from']} → {ch['to']} ({ch['jump']} version jump) "
            f"to fix {', '.join(card['advisories_removed'])} in {card['package']}@{card['version']}.\n\n"
            f"Changelog between these versions:\n{notes or '(not available)'}\n\nWhere the app uses {ch['package']}:\n{shown}")
    files = {s["file"]: (root / s["file"]).read_text(encoding="utf-8", errors="replace").splitlines() for s in snippets}
    windows = {(s["file"], n) for s in snippets for n in range(s["start"], s["start"] + len(s["lines"]))}

    def validate(a: dict) -> list:
        p = llm.check_enum(a, "breaking_risk", {"low", "medium", "high"})
        if not isinstance(a.get("explanation"), str) or not a["explanation"].strip():
            p.append("'explanation' must be 2-3 plain-English sentences")
        if not isinstance(a.get("summary"), str) or not a["summary"].strip():
            p.append("'summary' must be a short explanation")
        notes_ = a.get("notes")
        if not isinstance(notes_, list):
            p.append("'notes' must be a list")
            notes_ = []
        for n in notes_:
            if not isinstance(n, dict) or not n.get("text"):
                p.append("each note needs 'text'")
            elif n.get("file") and (n["file"] not in files or (n["file"], n.get("line")) not in windows):
                p.append(f"note cites {n.get('file')}:{n.get('line')}, which is not in the snippets shown")
        p += llm.check_ids(a.get("summary", "") + a.get("explanation", "") + " ".join(str(n.get("text")) for n in notes_ if isinstance(n, dict)), known_ids)
        return p

    return {"subject": f"{ch['package']}@{ch['from']}->{ch['to']}", "user": user, "validate": validate}
