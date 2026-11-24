# Software Supply Chain Guardian

Agentic supply-chain analysis for a public GitHub repository (Bosch hackathon). Paste a repo URL in the
dashboard; a LangGraph pipeline clones it at a pinned commit and runs each agent in turn. Every agent's
output shows up on the dashboard.

| # | Agent | Status | What it does |
|---|-------|--------|--------------|
| 1 | Repository Intake | built | Shallow clone (`--depth 1`, `core.symlinks=false`), records commit SHA, branch, author |
| 2 | Discovery | built | Finds manifests/lockfiles; direct + transitive deps from `package-lock.json` (v2/v3). No lockfile → generates one with `npm install --package-lock-only --ignore-scripts` and records command, npm version, time and sha256 as evidence. Python (`requirements*.txt`, `pyproject.toml`): full tree resolved with `uv pip compile` (nothing installed). `go.mod` gives direct deps; other ecosystems are reported as coverage gaps |
| 3 | SBOM | built | Merged CycloneDX 1.5 JSON (purls, scopes, licenses, hashes, dependency tree), cross-checked against `npm sbom` |
| 4 | Dependency graph | built | Nodes/edges, shortest introduction path per component, depth histogram, most depended-on packages |
| 5 | Container & CI/CD inspection | built | Dockerfile base-image pinning and risky `RUN`s; GitHub Actions pinning, `pull_request_target`, `write-all`, script injection; all with file:line |
| 6 | Vulnerability detection | built | OSV-Scanner on each lockfile (online, or offline with `GUARDIAN_OSV_OFFLINE=1`); CVSS band or advisory label, fixed version, introduction path; Trivy cross-check when installed |
| 7 | Suspicious-change detection | built | Install scripts, non-registry origins, typosquat lookalikes, missing lockfiles, unpinned Actions/base images, risky workflows, Dockerfile installs |
| 8 | Investigation & evidence | built | Evidence bundle per finding (facts / inference / unknowns, initial risk), Day 1 checklist, `report.md` + `report.json` |
| 9 | Investigate | built | Flagged packages: `npm pack --ignore-scripts` (never run), tarball hash vs lockfile, static checks on install hooks (download/exec/obfuscation/secrets/URLs), OSV `MAL-`. Workflow/Dockerfile findings: reads the lines, built-in checks (trusted publisher, official image + tag, curl\|sh, pull_request_target + PR checkout). AI verdict malicious/risky/harmless with file:line for everything not already harmless by rule |
| 10 | Prioritize | built | `min(10, CVSS × U × D × P × E × R)` with CISA KEV + EPSS; AI only labels reachability (R 1.0 / 1.0 / 0.7). Risky/malicious Investigate verdicts get rows too: malicious 10, risky 6.0 stand-in (× U × D × P; 1.0 each for repo config), or a 4.0 floor on an existing CVE row |
| 11 | Recommend Fix | built | For every band, critical to low: lowest OSV-vetted upgrade of the package(s) you control on every route that resolves to a fixed version (npm registry), else lockfile refresh or `overrides`; Python: `==safe` for a direct requirement, a `>=safe` line for a pulled-in one (PyPI, OSV-vetted, uv dry run); pin-and-review cards for supply-chain risks; config cards (pin action SHA, image digest, `npm ci`, trigger/permissions); plain-English explanation per card |
| 12 | Human Approval | built | Approve / Reject per fix card; **Approve applies the change** to one fixed copy of the app (branch `fix/guardian`), fixes adding up |
| 13 | Fixed app | built | Build, run & verify: relock, Docker build (Node or Python), app check (GET / in the sandbox; start command from `npm start`, Procfile, Django, FastAPI, Flask or Dockerfile CMD), tests, rescan; every changed project of a monorepo; rolls back a fix that breaks the build; runs the fixed app on http://localhost:3001; original vs fixed with reasons for what remains; downloadable patch |
| 14 | Report | built | Before/after risk and SBOM, remaining risk (open, rejected, accepted, awaiting), audit trail, AI summary limited to verified numbers; Markdown/JSON export |

AI: any OpenAI-compatible model via `backend/.env` (default `llama-3.3-70b-versatile` on Groq; `openai/gpt-oss-20b` also works).
Every AI answer passes a plain-code Validator (cited files/lines exist, values in range, no invented IDs);
failures fall back to the rule result. Without an API key everything still runs, rule-based.

No repository code runs during a scan. Nothing is cloned until a URL is submitted.

Dashboard: React + TypeScript with light and dark themes (toggle in the top bar), live per-agent status, vulnerability and suspicious-pattern tables, an evidence report with Markdown/JSON download,
an interactive dependency graph (hover tooltips, neighbour highlighting, labels on zoom, click for details
and the introduction path), a filterable SBOM table with download, and container/CI observations linked
to file:line.

Full explanation of every agent and every dashboard element: [docs/DASHBOARD_GUIDE.md](docs/DASHBOARD_GUIDE.md).

## Run

Needs Python 3.11+, [uv](https://docs.astral.sh/uv/) (resolves Python projects), Node 20+ (with npm 9.5+ for `npm sbom`), git, and
[OSV-Scanner](https://github.com/google/osv-scanner) on PATH. [Trivy](https://github.com/aquasecurity/trivy) is optional (cross-check).
On Windows: `scoop install osv-scanner trivy`.

First time only:

```powershell
cd backend; uv venv .venv; uv pip install --python .venv -r requirements.txt; cd ..
cd frontend; npm install; cd ..
```

For AI explanations, copy `backend/.env.example` to `backend/.env` and set `GROQ_API_KEY`
(optional: `GUARDIAN_LLM_MODEL`, `GITHUB_TOKEN`, `GUARDIAN_VALIDATE_TIMEOUT`, `GUARDIAN_RUNNER`).
Build, run & verify runs the fixed app **on this machine** by default (`GUARDIAN_RUNNER=local`: fast, but the
repo's own code runs without a sandbox, so only for repos you trust). Set `GUARDIAN_RUNNER=docker` to use the
Docker sandbox instead (start Docker Desktop first). Restart the backend after any change.

Then, in two terminals (backend first):

```powershell
cd backend; .venv\Scripts\python -m uvicorn app.main:app --port 8000
```

```powershell
cd frontend; npm run dev
```

Open http://localhost:5173 and paste e.g. `https://github.com/juice-shop/juice-shop` (takes about 3 minutes:
most of it is npm resolving Juice Shop's two lockfiles; OSV-Scanner adds about 10 seconds).

Alternatively `npm run build` in `frontend`, then the backend alone serves the dashboard on http://localhost:8000.

## Where data goes

`backend/data/` (gitignored): `workspaces/<scan>/repo` is the clone, `scans/<scan>/` holds the SBOM,
generated lockfiles and `npm sbom` outputs, `guardian.db` is the SQLite scan store. Set
`GUARDIAN_DATA_DIR` to put it elsewhere.

## Layout

```
backend/app/main.py          FastAPI: POST /api/scans, GET /api/scans[/id], artifact download
backend/app/pipeline.py      LangGraph orchestrator; add new agents to STEPS
backend/app/agents/*.py      one module per agent: run(state) -> (state_update, dashboard_result)
backend/app/db.py            SQLite scan store, agent list
frontend/src/                React + TypeScript dashboard (Vite)
```

Self-checks: `cd backend; .venv\Scripts\python -m tests.test_discovery; .venv\Scripts\python -m tests.test_detection`
