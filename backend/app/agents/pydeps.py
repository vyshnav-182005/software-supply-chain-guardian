"""Python ecosystem adapter: resolve, scan target, fix, dry-run.

Resolution: `uv pip compile <requirements.txt|pyproject.toml> --no-build` resolves the full dependency
tree from PyPI using wheels only (--no-build: no package's setup code is ever run). The output pins every
package and says which package pulled it in ("# via flask"), which gives the dependency edges.
Without uv, or when a package only exists as a source build, the project falls back to the direct
dependencies listed in the file (status "partial", reason shown).

Fixes edit requirements files: a direct package gets `name==safe`, a pulled-in package gets an extra
`name>=safe` line (pip and uv treat it as a constraint). pyproject.toml fixes are described for a person.
"""
import hashlib
import json
import re
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

UV = shutil.which("uv")
LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;#]+)\s*(?:;[^#]*)?(?:#\s*via\s+(.*))?$")


def norm(name: str) -> str:
    """PEP 503 name: lower case, runs of - _ . become -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{norm(name)}@{version}"


def read_text_any(path: Path) -> str:
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def python_version_for(project_dir: Path) -> str | None:
    """.python-version, runtime.txt (python-3.11.4) or pyproject requires-python (>=3.10)."""
    for f, rx in ((".python-version", r"(\d+\.\d+)"), ("runtime.txt", r"python-(\d+\.\d+)"),
                  ("pyproject.toml", r"requires-python\s*=\s*['\"][^0-9]*(\d+\.\d+)")):
        p = project_dir / f
        if p.is_file():
            m = re.search(rx, p.read_text(encoding="utf-8", errors="replace"))
            if m:
                return m.group(1)
    return None


def compile_tree(src: Path, out: Path, python_version: str | None = None) -> tuple[bool, str, str]:
    """uv pip compile, wheels only. Returns (ok, log, command shown in evidence)."""
    if not UV:
        return False, "uv is not installed", ""
    if src.read_bytes()[:2] in (b"\xff\xfe", b"\xfe\xff"):  # UTF-16 (PowerShell pip freeze): compile a UTF-8 copy
        copy = out.parent / f"{out.stem}.input.txt"
        copy.write_text(read_text_any(src), encoding="utf-8")
        src = copy
    cmd = [UV, "pip", "compile", str(src), "--no-build", "--annotation-style", "line", "--quiet", "-o", str(out)]
    if python_version:
        cmd += ["--python-version", python_version]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
                       cwd=src.parent)
    shown = "uv pip compile " + src.name + " --no-build --annotation-style line" + \
            (f" --python-version {python_version}" if python_version else "")
    return p.returncode == 0 and out.is_file(), (p.stdout + p.stderr)[-3000:], shown


def parse_compiled(text: str) -> list[tuple[str, str, list[str]]]:
    """[(name, version, [parents or '' for a direct requirement])]"""
    out = []
    for line in text.splitlines():
        m = LINE.match(line.strip())
        if not m:
            continue
        vias = [v.strip() for v in (m.group(3) or "").split(",") if v.strip()]
        parents = ["" if v.startswith("-r") or v.startswith("-c") or "(" in v else norm(v) for v in vias] or [""]
        out.append((m.group(1), m.group(2), parents))
    return out


def python_project(rel_file: str, path: Path, artifacts: Path, idx: int, components: dict, edges: set,
                   direct_fallback) -> dict:
    """One requirements*.txt or pyproject.toml. direct_fallback(rel, path, components, edges) parses only the
    listed packages when the full resolution is not possible."""
    pid = f"project:{rel_file}"
    scope = "dev" if re.search(r"dev|test|lint|doc", path.name, re.I) else "runtime"
    out = artifacts / f"py-resolved-{idx}" / "requirements.txt"  # named so OSV-Scanner recognises it
    out.parent.mkdir(parents=True, exist_ok=True)
    pyver = python_version_for(path.parent)
    ok, log, shown = compile_tree(path, out, pyver)
    if not ok:
        proj = direct_fallback(rel_file, path, components, edges)
        why = "uv is not installed" if not UV else \
            ("a package is only published as source and would need its build code run" if "--no-build" in log or
             "build" in log.lower() else "uv could not resolve: " + log.strip().splitlines()[-1][:200] if log.strip() else "")
        proj["notes"].append(f"Full tree not resolved: {why}")
        proj["evidence"]["resolve_log"] = log[-1500:]
        return proj
    resolved = parse_compiled(out.read_text(encoding="utf-8"))
    ids = {norm(n): purl(n, v) for n, v, _ in resolved}
    for name, version, parents in resolved:
        cid = purl(name, version)
        c = components.setdefault(cid, {
            "id": cid, "name": norm(name), "version": version, "ecosystem": "pypi", "purl": cid,
            "direct": False, "scope": scope, "license": None, "origin": "pypi.org", "resolved": None,
            "integrity": None, "install_script": False, "projects": [], "install_paths": 1})
        if scope == "runtime":
            c["scope"] = "runtime"
        if pid not in c["projects"]:
            c["projects"].append(pid)
        for parent in parents:
            if parent == "":
                c["direct"] = True
                edges.add((pid, cid, scope))
            elif parent in ids:
                edges.add((ids[parent], cid, "runtime"))
    direct = sum(1 for _, _, ps in resolved if "" in ps)
    return {"id": pid, "path": rel_file, "dir": Path(rel_file).parent.as_posix(), "ecosystem": "pypi",
            "manifest": rel_file.removeprefix("./"), "name": rel_file, "lockfile": out.name,
            "lock_source": "generated", "status": "parsed", "component_count": len(resolved),
            "declared_direct": direct, "scan_target": out.relative_to(artifacts).as_posix(),
            "evidence": {"command": shown, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
                         "artifact": out.relative_to(artifacts).as_posix(), "python": pyver or "uv default"},
            "notes": [f"Full tree resolved with uv for Python {pyver or '(uv default)'}: wheels only, no build code run"]}


# ---------------------------------------------------------------- fixes

_versions: dict[str, list] = {}


def pypi_versions(name: str) -> list:
    from packaging.version import InvalidVersion, Version
    if name not in _versions:
        try:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{norm(name)}/json", timeout=30) as r:
                data = json.load(r)
            vs = []
            for k, files in data.get("releases", {}).items():
                try:
                    v = Version(k)
                except InvalidVersion:
                    continue
                if not v.is_prerelease and files and not all(f.get("yanked") for f in files):
                    vs.append(v)
            _versions[name] = sorted(vs)
        except Exception:
            _versions[name] = []
    return _versions[name]


def safe_version(name: str, current: str, need: str, serious) -> tuple[str | None, list]:
    """Lowest PyPI version >= need with no known high/critical advisory (serious(name, v) -> ids)."""
    from packaging.version import Version
    rejected = []
    for v in [v for v in pypi_versions(name) if v >= Version(need)][:30]:
        bad = serious(name, str(v))
        if not bad:
            return str(v), rejected
        rejected.append({"version": str(v), "because": [f"{name}@{v} {a}" for a in bad[:3]]})
    return None, rejected


def edit_requirements(path: Path, package: str, spec: str) -> tuple[str, str | None]:
    """Set `package` to `spec` (e.g. '==2.3.1' or '>=2.3.1') in a requirements file, keeping its encoding.
    Returns (detail, previous spec or None if the line was added)."""
    raw = path.read_bytes()
    utf16 = raw[:2] in (b"\xff\xfe", b"\xfe\xff")
    lines = read_text_any(path).splitlines()
    rx = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*([<>=!~][^;#]*)?(.*)$")
    previous = None
    for i, line in enumerate(lines):
        m = rx.match(line)
        if m and not line.lstrip().startswith(("#", "-")) and norm(m.group(1)) == norm(package):
            previous = (m.group(3) or "").strip() or "(any)"
            lines[i] = f"{m.group(1)}{m.group(2) or ''}{spec}{m.group(4) or ''}"
            break
    else:
        lines.append(f"{package}{spec}  # added by Supply Chain Guardian (pins a pulled-in package)")
    text = "\n".join(lines) + "\n"
    path.write_bytes(text.encode("utf-16") if utf16 else text.encode("utf-8"))
    return (f"{package}: {previous} -> {spec}" if previous else f"added {package}{spec}"), previous


def undo_requirements(path: Path, package: str, previous: str | None) -> None:
    lines = read_text_any(path).splitlines()
    rx = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*([<>=!~][^;#]*)?(.*)$")
    for i, line in enumerate(lines):
        m = rx.match(line)
        if m and norm(m.group(1)) == norm(package):
            if previous is None:
                lines.pop(i)
            else:
                lines[i] = f"{m.group(1)}{m.group(2) or ''}{'' if previous == '(any)' else previous}{m.group(4) or ''}"
            break
    utf16 = path.read_bytes()[:2] in (b"\xff\xfe", b"\xfe\xff")
    text = "\n".join(lines) + "\n"
    path.write_bytes(text.encode("utf-16") if utf16 else text.encode("utf-8"))


def check_resolves(requirements: Path) -> tuple[bool, str]:
    """Dry run: does uv resolve the edited requirements (wheels only)?"""
    tmp_out = requirements.parent / ".guardian-check.txt"
    ok, log, _ = compile_tree(requirements, tmp_out, python_version_for(requirements.parent))
    tmp_out.unlink(missing_ok=True)
    for extra in requirements.parent.glob(".guardian-check.input.txt"):
        extra.unlink(missing_ok=True)
    return ok, log
