"""Discovery Agent: find manifests/lockfiles and build a normalized component inventory.

Ecosystem adapters (all emit the same component/edge shape):
  npm    package.json + package-lock.json (v2/v3). With no lockfile, one is generated
         with `npm install --package-lock-only --ignore-scripts` (resolves versions from
         the registry, installs nothing, runs no scripts) and recorded as evidence.
  pypi   requirements*.txt (direct deps only; no resolver).
  golang go.mod (direct + `// indirect`; parent edges not known without `go mod graph`).
Anything else is reported as detected-but-unsupported so coverage gaps are explicit.

Component: {id(purl), name, version, ecosystem, purl, direct, scope, license, origin,
            resolved, integrity, install_script, projects}
Edge: {source, target, kind}  (project root ids look like "project:<path>")
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import quote, urlparse

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}
UNSUPPORTED = {
    "pyproject.toml": "pypi", "Pipfile": "pypi", "poetry.lock": "pypi", "Pipfile.lock": "pypi",
    "pom.xml": "maven", "build.gradle": "maven", "build.gradle.kts": "maven",
    "Cargo.toml": "cargo", "Gemfile": "gem", "composer.json": "composer",
}
NPM = shutil.which("npm") or "npm"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def npm_purl(name: str, version: str) -> str:
    # purl spec: npm scope "@x" is the namespace and is percent-encoded
    return f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"


def origin_of(resolved: str | None) -> str:
    if not resolved:
        return "unknown"
    if resolved.startswith(("git", "github:")) or "git+" in resolved:
        return "git"
    if resolved.startswith("file:") or "://" not in resolved:
        return "local"
    return urlparse(resolved).netloc


# ---------------------------------------------------------------- npm

def generate_lockfile(project_dir: Path, artifacts: Path, idx: int) -> dict:
    """Resolve a lockfile without installing packages or running scripts."""
    base = [NPM, "install", "--package-lock-only", "--ignore-scripts", "--package-lock=true",
            "--no-audit", "--no-fund"]
    for extra in ([], ["--legacy-peer-deps"]):
        cmd = base + extra
        out = subprocess.run(cmd, cwd=project_dir, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=900)
        if out.returncode == 0 and (project_dir / "package-lock.json").exists():
            lock = project_dir / "package-lock.json"
            saved = artifacts / f"generated-lock-{idx}.json"
            shutil.copy(lock, saved)
            npm_version = subprocess.run([NPM, "--version"], capture_output=True, text=True).stdout.strip()
            return {"command": " ".join(["npm", *cmd[1:]]), "npm_version": npm_version,
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "sha256": sha256(lock), "artifact": saved.name}
    raise RuntimeError(f"npm could not resolve a lockfile: {out.stderr.strip()[-400:]}")


def resolve_dep(packages: dict, from_path: str, dep: str) -> str | None:
    """Node's module resolution over lockfile paths: nearest node_modules/<dep> walking up."""
    base = from_path
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in packages:
            meta = packages[cand]
            return meta["resolved"] if meta.get("link") else cand
        if not base:
            return None
        i = base.rfind("/node_modules/")
        base = base[:i] if i >= 0 else ""


def parse_npm_lock(lock: dict, project_id: str, components: dict, edges: set, warnings: list):
    packages = lock.get("packages")
    if not packages:
        raise ValueError(f"lockfileVersion {lock.get('lockfileVersion')} has no 'packages' map (v1 unsupported)")

    def comp_id(path):
        if path == "":
            return project_id
        meta = packages[path]
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        return npm_purl(name, meta.get("version", "0.0.0"))

    for path, meta in packages.items():
        if path == "" or meta.get("link"):
            continue
        cid = comp_id(path)
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        scope = "dev" if meta.get("dev") else "optional" if meta.get("optional") or meta.get("devOptional") else "runtime"
        c = components.setdefault(cid, {
            "id": cid, "name": name, "version": meta.get("version", ""), "ecosystem": "npm",
            "purl": cid, "direct": False, "scope": scope, "license": meta.get("license"),
            "origin": "bundled" if meta.get("inBundle") else origin_of(meta.get("resolved")), "resolved": meta.get("resolved"),
            "integrity": meta.get("integrity"), "install_script": bool(meta.get("hasInstallScript")),
            "platform": meta.get("os") or meta.get("cpu"),  # OS/CPU-restricted (e.g. fsevents)
            "projects": [], "install_paths": 0,
        })
        if scope == "runtime":  # runtime anywhere wins over dev/optional
            c["scope"] = "runtime"
        c["install_paths"] += 1
        if project_id not in c["projects"]:
            c["projects"].append(project_id)

    unresolved = 0
    for path, meta in packages.items():
        if meta.get("link"):
            continue
        groups = [("dependencies", "runtime"), ("optionalDependencies", "optional"), ("peerDependencies", "peer")]
        if path == "":
            groups.append(("devDependencies", "dev"))
        src = comp_id(path)
        for field, kind in groups:
            for dep in meta.get(field) or {}:
                target = resolve_dep(packages, path, dep)
                if target is None or target not in packages:
                    unresolved += kind == "runtime"
                    continue
                tid = comp_id(target)
                edges.add((src, tid, kind))
                if path == "":
                    components[tid]["direct"] = True
    if unresolved:
        warnings.append(f"{project_id}: {unresolved} runtime dependency references could not be resolved in the lockfile")


def npm_project(rel: str, pdir: Path, artifacts: Path, idx: int, components, edges, warnings) -> dict:
    pkg = json.loads((pdir / "package.json").read_text(encoding="utf-8"))
    pid = f"project:{rel}"
    proj = {"id": pid, "path": rel, "ecosystem": "npm", "manifest": "package.json" if rel == "." else f"{rel}/package.json",
            "name": pkg.get("name") or Path(rel).name, "version": pkg.get("version"),
            "declared_direct": sum(len(pkg.get(k) or {}) for k in
                                   ("dependencies", "devDependencies", "optionalDependencies")),
            "notes": [], "evidence": {}}
    for other in ("yarn.lock", "pnpm-lock.yaml"):
        if (pdir / other).exists():
            proj["notes"].append(f"{other} present but not parsed; versions come from npm's lockfile")
    lock_path = next((pdir / f for f in ("package-lock.json", "npm-shrinkwrap.json") if (pdir / f).exists()), None)
    if lock_path:
        proj["lockfile"], proj["lock_source"] = lock_path.name, "committed"
        proj["evidence"] = {"sha256": sha256(lock_path)}
    else:
        if (pdir / ".npmrc").exists() and "package-lock=false" in (pdir / ".npmrc").read_text(errors="replace"):
            proj["notes"].append(".npmrc disables lockfiles (package-lock=false)")
        proj["evidence"] = generate_lockfile(pdir, artifacts, idx)
        proj["lockfile"], proj["lock_source"] = "package-lock.json", "generated"
        proj["notes"].append("No committed lockfile: versions resolved from the registry at "
                             f"{proj['evidence']['generated_at']} (time-dependent)")
        lock_path = pdir / "package-lock.json"
    before = len(components)
    parse_npm_lock(json.loads(lock_path.read_text(encoding="utf-8")), pid, components, edges, warnings)
    proj["status"] = "parsed"
    proj["component_count"] = sum(1 for c in components.values() if pid in c["projects"])
    proj["new_components"] = len(components) - before
    return proj


# ---------------------------------------------------------------- pypi / go (direct only)

REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(==\s*([^\s;#]+)|[<>=!~].*)?")


def read_text_any(path: Path) -> str:
    """Text in UTF-8 or UTF-16 (Windows PowerShell's `pip freeze > requirements.txt` writes UTF-16 with a BOM)."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def requirements_project(rel: str, path: Path, components, edges) -> dict:
    pid = f"project:{rel}"
    pinned = unpinned = 0
    for line in read_text_any(path).splitlines():
        m = REQ_LINE.match(line.strip())
        if not m or line.strip().startswith(("-", "#")):
            continue
        name, version = m.group(1).lower(), m.group(3) or ""
        pinned += bool(version)
        unpinned += not version
        cid = f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
        c = components.setdefault(cid, {
            "id": cid, "name": name, "version": version or "(unpinned)", "ecosystem": "pypi",
            "purl": cid, "direct": True, "scope": "runtime", "license": None, "origin": "pypi.org",
            "resolved": None, "integrity": None, "install_script": False, "projects": [], "install_paths": 1})
        c["projects"].append(pid)
        edges.add((pid, cid, "runtime"))
    return {"id": pid, "path": rel, "ecosystem": "pypi", "manifest": str(path.name), "name": rel,
            "lockfile": None, "lock_source": "none", "status": "partial",
            "component_count": pinned + unpinned, "evidence": {"sha256": sha256(path)},
            "notes": [f"{pinned} pinned, {unpinned} unpinned; transitive dependencies not resolved (no lockfile)"]}


def gomod_project(rel: str, path: Path, components, edges) -> dict:
    pid = f"project:{rel}"
    text = path.read_text(encoding="utf-8", errors="replace")
    count = 0
    for mod, ver, indirect in re.findall(r"^\s*(?:require\s+)?([\w.\-~/]+\.[\w.\-~/]+)\s+(v[^\s]+)(\s*//\s*indirect)?",
                                         text, re.M):
        cid = f"pkg:golang/{mod}@{ver}"
        c = components.setdefault(cid, {
            "id": cid, "name": mod, "version": ver, "ecosystem": "golang", "purl": cid,
            "direct": not indirect, "scope": "runtime", "license": None, "origin": "proxy.golang.org",
            "resolved": None, "integrity": None, "install_script": False, "projects": [], "install_paths": 1})
        c["projects"].append(pid)
        edges.add((pid, cid, "runtime" if not indirect else "indirect"))
        count += 1
    return {"id": pid, "path": rel, "ecosystem": "golang", "manifest": "go.mod", "name": rel,
            "lockfile": "go.sum" if (path.parent / "go.sum").exists() else None,
            "lock_source": "committed", "status": "partial", "component_count": count,
            "evidence": {"sha256": sha256(path)},
            "notes": ["Indirect modules listed but their parent edges need `go mod graph` (not run)"]}


# ---------------------------------------------------------------- agent

def find_manifests(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            yield Path(dirpath) / f


def run(state: dict) -> tuple[dict, dict]:
    root = Path(state["workdir"])
    artifacts = Path(state["artifacts"])
    components, edges, warnings, projects, unsupported = {}, set(), [], [], []
    npm_workspace_roots = []

    for f in find_manifests(root):
        rel = f.parent.relative_to(root).as_posix() or "."
        try:
            if f.name == "package.json":
                if any(f.parent.is_relative_to(w) for w in npm_workspace_roots):
                    continue  # workspace member: covered by the workspace root's lockfile
                if json.loads(f.read_text(encoding="utf-8")).get("workspaces"):
                    npm_workspace_roots.append(f.parent)
                projects.append(npm_project(rel, f.parent, artifacts, len(projects), components, edges, warnings))
            elif re.fullmatch(r"requirements.*\.txt", f.name):
                projects.append(requirements_project(f"{rel}/{f.name}", f, components, edges))
            elif f.name == "go.mod":
                projects.append(gomod_project(rel, f, components, edges))
            elif f.name in UNSUPPORTED:
                unsupported.append({"path": f.relative_to(root).as_posix(), "ecosystem": UNSUPPORTED[f.name]})
        except Exception as e:  # one broken manifest must not hide the rest; it is reported instead
            projects.append({"id": f"project:{rel}", "path": rel, "manifest": f.name, "status": "failed",
                             "ecosystem": "npm" if f.name == "package.json" else "?", "notes": [str(e)],
                             "component_count": 0, "evidence": {}})
            warnings.append(f"{f.relative_to(root).as_posix()}: {e}")

    for u in unsupported:
        warnings.append(f"{u['path']}: {u['ecosystem']} manifest detected but not supported yet (coverage gap)")
    if not projects:
        warnings.append("No supported manifests found: inventory is empty because coverage is zero, not because the repo is clean")

    comps = sorted(components.values(), key=lambda c: (c["ecosystem"], c["name"], c["version"]))
    edge_list = [{"source": s, "target": t, "kind": k} for s, t, k in sorted(edges)]
    direct = sum(c["direct"] for c in comps)
    partial = warnings or any(p["status"] != "parsed" for p in projects)
    public = {
        "projects": projects, "unsupported": unsupported, "warnings": warnings,
        "ecosystems": sorted({p["ecosystem"] for p in projects}),
        "components": comps,
        "stats": {"components": len(comps), "direct": direct, "transitive": len(comps) - direct,
                  "edges": len(edge_list), "install_scripts": sum(c["install_script"] for c in comps)},
        "_status": "partial" if partial else "done",
        "_summary": f"{len(projects)} project(s), {len(comps)} components ({direct} direct)",
    }
    return {"projects": projects, "components": comps, "edges": edge_list}, public
