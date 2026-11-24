"""Run: .venv/Scripts/python -m tests.test_discovery"""
from app.agents.discovery import npm_purl, parse_npm_lock, resolve_dep

LOCK = {"lockfileVersion": 3, "packages": {
    "": {"name": "app", "dependencies": {"a": "^1"}, "devDependencies": {"d": "1"}},
    "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2"}},
    "node_modules/b": {"version": "3.0.0"},                       # hoisted, wrong major
    "node_modules/a/node_modules/b": {"version": "2.0.0", "dependencies": {"c": "*"}},
    "node_modules/c": {"version": "1.0.0", "hasInstallScript": True},
    "node_modules/d": {"version": "1.0.0", "dev": True},
    "node_modules/@s/e": {"version": "1.0.0"},
}}

if __name__ == "__main__":
    p = LOCK["packages"]
    assert resolve_dep(p, "node_modules/a", "b") == "node_modules/a/node_modules/b"   # nested wins
    assert resolve_dep(p, "node_modules/a/node_modules/b", "c") == "node_modules/c"  # walks up
    assert resolve_dep(p, "", "zzz") is None
    assert npm_purl("@s/e", "1.0.0") == "pkg:npm/%40s/e@1.0.0"
    comps, edges, warn = {}, set(), []
    parse_npm_lock(LOCK, "project:.", comps, edges, warn)
    assert ("pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0", "runtime") in edges
    assert ("project:.", "pkg:npm/d@1.0.0", "dev") in edges
    assert comps["pkg:npm/a@1.0.0"]["direct"] and not comps["pkg:npm/b@2.0.0"]["direct"]
    assert comps["pkg:npm/d@1.0.0"]["scope"] == "dev" and comps["pkg:npm/c@1.0.0"]["install_script"]
    # requirements.txt saved as UTF-16 (PowerShell `pip freeze > requirements.txt`) is still read
    import tempfile
    from pathlib import Path
    from app.agents.discovery import requirements_project
    f = Path(tempfile.mkdtemp()) / "requirements.txt"
    f.write_text("flask==2.0.1\nrequests>=2\n", encoding="utf-16")
    c16 = {}
    assert requirements_project("x", f, c16, set())["component_count"] == 2 and "pkg:pypi/flask@2.0.1" in c16
    print("discovery ok")
