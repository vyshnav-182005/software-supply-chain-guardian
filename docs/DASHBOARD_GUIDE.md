# Supply Chain Guardian: Dashboard Guide

This guide explains every screen of the dashboard: what each tab, tile, column, badge and label
means, where the numbers come from, and how the numbers on different tabs relate to each other.

The running example is **OWASP Juice Shop** (`https://github.com/juice-shop/juice-shop`, commit
`c9f99228d9d5`). Numbers can differ slightly between scans: Juice Shop has no committed lockfile, so
package versions are resolved from the npm registry at scan time, and the AI may judge a few items
differently.

Contents

1. [What the Guardian does, in one picture](#1-what-the-guardian-does-in-one-picture)
2. [Setup, settings and running a demo](#2-setup-settings-and-running-a-demo)
3. [Home page: start, stop and delete scans](#3-home-page-start-stop-and-delete-scans)
4. [Scan page: header and agent cards](#4-scan-page-header-and-agent-cards)
5. [Tab: Overview](#5-tab-overview)
6. [Tab: Dependency graph](#6-tab-dependency-graph)
7. [Tab: SBOM](#7-tab-sbom)
8. [Tab: Container & CI/CD](#8-tab-container--cicd)
9. [Tab: Vulnerabilities](#9-tab-vulnerabilities)
10. [Tab: Suspicious changes](#10-tab-suspicious-changes)
11. [Tab: Evidence report](#11-tab-evidence-report)
12. [Tab: Investigation](#12-tab-investigation)
13. [Tab: Prioritized risks](#13-tab-prioritized-risks)
14. [Tab: Fixes & approval](#14-tab-fixes--approval)
15. [Tab: Fixed app & report](#15-tab-fixed-app--report)
16. [How the numbers connect across tabs](#16-how-the-numbers-connect-across-tabs)
17. [Facts, AI inference and the Validator](#17-facts-ai-inference-and-the-validator)
18. [Glossary](#18-glossary)

---

## 1. What the Guardian does, in one picture

```
 GitHub URL
    │
    ▼
 1 Repository Intake ─ 2 Discovery ─ 3 SBOM ─ 4 Dependency Graph ─ 5 Container & CI/CD
    │                                                                    │
    ├──────────────► 6 Vulnerability Detection (OSV-Scanner, Trivy)       │
    └──────────────► 7 Suspicious-Change Detection (rules) ◄─────────────┘
                              │
                     8 Investigation & Evidence (evidence report)
                              │
                     9 Investigate (look inside flagged packages and config lines; AI verdict)
                              │
                    10 Prioritize (one score per package or finding; AI reachability label)
                              │
                    11 Recommend Fix (one fix card per change; AI explanation)
                              │
                    12 Human Approval ── you click Approve / Reject
                              │
                    13 Fixed app (each Approve applies its fix to one fixed copy; build, verify, run it)
                              │
                    14 Report (before vs after, remaining risk, audit trail)
```

Agents 1 to 12 run automatically, one after another, when you start a scan. Agents 13 and 14 run
after you approve fixes. **No code from the scanned repository is ever executed during a scan.**
The fixed app is built, tested and run only after your approval, and only in Docker.

---

## 2. Setup, settings and running a demo

### Start the app

Two terminals, backend first:

```powershell
cd C:\Academics\project\bosch-hackathon\backend; .venv\Scripts\python -m uvicorn app.main:app --port 8000
```

```powershell
cd C:\Academics\project\bosch-hackathon\frontend; npm run dev
```

Open http://localhost:5173. **After any backend code or `.env` change, restart the backend** (it does
not reload by itself). The frontend reloads by itself; just refresh the page.

### Settings (`backend\.env`, never committed)

| Setting | What it does | Default |
|---|---|---|
| `GROQ_API_KEY` | Key for the AI (Groq). Without it everything still runs, rule-based, and the dashboard says "AI explanation unavailable" | none |
| `GUARDIAN_LLM_MODEL` | Which model to use | `llama-3.3-70b-versatile` (`openai/gpt-oss-20b` also works) |
| `GUARDIAN_LLM_BASE_URL` | Any OpenAI-compatible endpoint | Groq |
| `GITHUB_TOKEN` | Optional. Raises GitHub's limit (60 per hour) for changelog lookups in Recommend Fix | none |
| `GUARDIAN_OSV_OFFLINE=1` | Use OSV's offline database instead of the online API | online |
| `GUARDIAN_VALIDATE_TIMEOUT` | Seconds allowed for build + tests when validating a fix | 1200 |
| `GUARDIAN_FIX_DRYRUN=off` | Skip the npm compatibility check of fix cards during the scan (faster scans) | on |
| `GUARDIAN_ALLOW_UNSANDBOXED=1` | If Docker is not running, run build/tests locally without a sandbox (runs the repo's code on your machine) | off |
| `GUARDIAN_DATA_DIR` | Where clones, evidence files and the database are stored | `backend\data` |

### Tools the backend uses

OSV-Scanner (required), Trivy (optional cross-check), npm and git. Validate needs **Docker Desktop
running** to build and test fixes.

### How to run a demo (about 10 minutes)

1. Start Docker Desktop, the backend and the frontend.
2. On the home page paste `https://github.com/juice-shop/juice-shop` (or NodeGoat, which builds
   faster) and click **Start scan**. Watch the 12 agent cards turn green (2 to 4 minutes).
3. **Overview** → the size of the supply chain (1,657 packages, 154 direct).
4. **Dependency graph** → search `crypto-js@3.3.0` to show how a package nobody asked for gets in.
5. **Vulnerabilities** → 57 known advisories on 22 packages.
6. **Suspicious changes** → 34 non-CVE risks (install scripts, unpinned actions...).
7. **Investigation** → what the agent found inside those packages and files.
8. **Prioritized risks** → the single ranked list with the formula on every row.
9. **Fixes & approval** → read a card's explanation, click **Approve**.
10. **Fixed app & report** → click **Build, run & verify fixed app**; when it finishes, click **Open app**
    to use the fixed Juice Shop at http://localhost:3001, and compare original vs fixed.

---

## 3. Home page: start, stop and delete scans

- **URL box + Start scan**: accepts only public `https://github.com/<owner>/<repo>` URLs. The repo is
  cloned only when you click Start scan.
- **Recent scans** (last 50): repository, short commit ID, status, start time. Click a row to open it.
- **Status badges**: `queued` → `running` → `completed`, or `failed` (an agent hit an error; the red
  banner on the scan page says which), `cancelling` / `cancelled` (you stopped it).
- **■ Stop** (amber, only while running): the agent that is working finishes its current step, then
  the scan stops and is marked `cancelled`.
- **🗑 Delete** (red): after a confirm prompt, removes the scan's results, its evidence files
  (`backend\data\scans\<id>`), the cloned repo and any fix branches (`backend\data\workspaces\<id>`).
  Refused while the scan is running or one of its fixes is being validated.
- **☀ Light / ☾ Dark** (top right): theme, remembered per browser.

---

## 4. Scan page: header and agent cards

**Header**: repository (link), branch, the exact commit scanned, commit date, author and message,
and the scan status.

**Agent cards** (12): one per agent, in pipeline order. Each shows a status icon, a one-line summary
and how long it took. Click a card to jump to its tab.

| Icon / colour | Meaning |
|---|---|
| ✓ green | done |
| ! amber | partial: finished, but something was not fully covered. The summary or tab says what |
| ◌ blue, spinning | running |
| ✕ red | failed (hover for the error). Later agents are then `skipped` |
| ○ grey | pending |

Juice Shop example summaries: Intake `juice-shop/juice-shop @ c9f99228d9d5 (1498 files)`;
Discovery `2 project(s), 1657 components (154 direct)`; Vulnerability `57 advisories on 22 packages
(7 critical, 22 high)`; Suspicious changes `34 findings across 7 rules`; Prioritize
`… packages ranked …`; Recommend Fix `… fix cards`; Human Approval `… fixes awaiting a decision`.

---

## 5. Tab: Overview

**Tiles**

| Tile | Juice Shop | Meaning |
|---|---|---|
| Components | 1657 | Every distinct package@version in the project (backend + Angular frontend together) |
| Direct | 154 | Packages the project lists itself in `package.json` |
| Transitive | 1503 | Packages pulled in by other packages (nobody asked for them directly) |
| Dependency edges | 3381 | "A needs B" links between packages |
| Max depth | 10 | The longest chain from the project to a package |
| Install scripts | 14 | Packages that run their own code when installed |
| CI/container warnings | 9 | Warning-level observations on the Container & CI/CD tab |
| SBOM | CDX 1.5 | The SBOM format produced (CycloneDX 1.5) |
| Critical / high advisories | 7 / 22 | From the Vulnerabilities tab |
| Suspicious-pattern findings | 34 | From the Suspicious changes tab |

**Discovered projects**: each `package.json` found (Juice Shop has two: root and `frontend/`). Columns:
manifest, ecosystem, lockfile (`committed` = from the repo, `generated` = created during the scan
because the repo has none), number of packages, status, and evidence (the exact npm command,
npm version, time, file hash and a download link).

**Coverage gaps** (amber card, only when needed): anything not checked, for example unsupported
languages. Nothing listed here is ever reported as "clean".

**Components by dependency depth**: how many packages sit at each depth. Most of Juice Shop's
packages are 2 to 4 levels down, invisible in `package.json`.

**Most depended-on packages**: the 10 packages the most other packages rely on.

**Scan provenance**: the exact commit, clone command, file count and SBOM hash, so the scan can be
reproduced.

---

## 6. Tab: Dependency graph

An interactive map of every package (dot) and every "needs" link (line).

- **Colours**: white/black = the repository; purple = a project; teal = direct dependency; blue =
  transitive; grey = dev-only (used for building/testing, not shipped); orange ring = has an install
  script; yellow/amber = the selected path; pink = the dot under your mouse and its neighbours.
- **Hover** a dot: name@version, direct or transitive, scope, depth, number of dependents, install
  script. **Click**: the side panel opens. **Scroll**: zoom (past ~2.5× every dot is labelled).
- **Search box**: type a package (`crypto-js@3.3.0`) to jump to it.
- **All / Hide dev / Direct only**: show everything, only what ships, or just the top level.
- **Side panel**: "Introduced via" (the shortest chain from the repo, e.g. juice-shop → pdfkit@0.11.0
  → crypto-js@3.3.0), package ID (purl), scope, license, where it was downloaded from, integrity hash,
  install script yes/no, and which packages require it and which it requires.
- The node count is packages + 3 (the repository and its two projects).

---

## 7. Tab: SBOM

The Software Bill of Materials: the official list of everything inside the software.

- **Header**: CycloneDX 1.5, number of components and dependency entries, and **Download SBOM (JSON)**.
- **Independent cross-check**: npm's own SBOM tool counted the same packages
  (1108 for the backend and 814 for the frontend, `match`).
- **Component table** (filters: text, direct/transitive/has install script, scope):
  package, version, ecosystem, relationship, "introduced via" (the package that pulled it in),
  scope (runtime / dev / optional), license, origin (download host).

---

## 8. Tab: Container & CI/CD

How the software is built and shipped (Dockerfiles and GitHub Actions workflows), read without
running anything.

- **Tiles**: Dockerfiles 3, base images 6, workflows 16, action references 94, not SHA-pinned 7,
  warnings 9.
- **Observations table**: level (WARNING / NOTICE / INFO), what was seen, and evidence: a link to the
  exact file line at the scanned commit, plus the line itself.
- **Container base images**: each `FROM` and how it is pinned (digest = exact, tag = can change,
  none/latest = whatever is newest).
- **GitHub Actions**: every `uses:` step and whether it is pinned to an exact commit (SHA).

These are observations, not scores. The Suspicious changes tab turns them into findings.

---

## 9. Tab: Vulnerabilities

Known security advisories (CVE / GHSA) that affect the exact package versions in the project,
found by OSV-Scanner, with Trivy as a second opinion.

- **Tiles**: critical 7, high 22, medium 26, low 2, unrated 0, **packages affected 22**.
  **57 advisories on 22 packages**: one package can have several advisories (lodash 2.4.2 has
  several), so advisories ≥ packages. Click a tile to filter.
- **Scan evidence**: per project, the OSV-Scanner version, online/offline mode, time, exact command,
  the lockfile scanned and its hash, the raw output (download), and how many of Trivy's results agree.
- **Advisory table**: severity with CVSS score, advisory ID (links to osv.dev) and CVE IDs, package
  (direct/transitive), introduced via, fixed-in version ("no fix" if none exists), and the title.
  Click a row for the CVSS vector, all IDs, weakness type, all fixed versions and Trivy's confirmation.
- **Severity** comes from the CVSS score: ≥9 critical, ≥7 high, ≥4 medium, >0 low. Without a score
  the advisory's own label is used; with neither it is "unrated".

---

## 10. Tab: Suspicious changes

Supply-chain risks that are **not** known vulnerabilities. Juice Shop: **34 findings across 7 rules**.

| Rule | What it means | Juice Shop | Severity |
|---|---|---|---|
| install-script | The package runs code when installed | 14 | medium (prod) / low (dev, optional) |
| unpinned-action | A GitHub Action used through a movable tag instead of an exact commit | 7 | medium (third-party) / low (GitHub's own) |
| base-image | A Docker base image not locked to an exact digest | 5 | medium (no tag/latest) / low (version tag) |
| build-install | A Dockerfile installs packages without a lockfile | 3 | medium / low (global tool) / high (curl\|sh) |
| no-lockfile | The project has no committed lockfile | 2 | medium |
| typosquat | The name is one typo away from a popular package | 2 | low |
| workflow-risk | A risky workflow setting (e.g. `pull_request_target`) | 1 | medium / high |

- **Tiles**: high / medium / low counts and rules triggered.
- **Rule chips**: click to filter one rule.
- **Not applicable**: "modified lockfile", "new dependency" and "version bump" need two commits to
  compare; a scan looks at one commit, so they are listed, not silently skipped.
- **Table**: severity, finding, **basis** (`fact` = read straight from a file; `indicator` = a guess a
  person should check, used for typosquats), evidence (file:line link or lockfile entry) and why it
  matters.

---

## 11. Tab: Evidence report

The Day-1 style report: one **evidence bundle** per vulnerability or suspicious finding
(57 + 34 = **91** for Juice Shop).

- **Initial risk tiles**: a simple first rating (critical 7, high 20, medium 44, low 20). Rule:
  the advisory's band, one level lower if the package is dev-only; suspicious findings keep their
  rule severity. This is a first look; **Prioritized risks** is the final ranking.
- **Acceptance checklist**: the requirements, each ✓ or ✕ from what actually ran.
- **Coverage and gaps**: what was not checked.
- **Evidence bundles**: expand one to see the dependency path, verified facts, inference, unknowns
  (e.g. "reachability not analysed") and evidence links.
- **Report (Markdown) / JSON**: downloads.

---

## 12. Tab: Investigation

Looks deeper at what Suspicious changes flagged.

**Reconciliation line** at the top, for example:
**34 suspicious findings = 16 package findings (16 packages investigated) + 16 config findings
(16 investigated) + 2 repo-wide rule facts (not investigated)**. This is why Suspicious changes shows
34 and Investigation shows 32.

**Tiles**: malicious / risky / harmless / needs review, each split as "N packages + M config", plus
"Packages investigated" and "Config findings investigated".

**Packages table** (install-script and typosquat findings; at most 25 per scan):
the package is downloaded with `npm pack --ignore-scripts` (never installed or run), its hash is
compared with the lockfile, and its install scripts are read. Columns: verdict (+ confidence),
package, why it was flagged, tool facts (hash match, install hooks, static-check matches, OSV
malware advisory), reason. Click a row for the cited lines with the code highlighted.

Built-in checks on install code: **download** (curl, wget, http.get, fetch…), **exec**
(child_process, exec, spawn, eval…), **download-and-execute** (both), **obfuscation** (long base64,
hex escapes), **secrets** (`.npmrc`, `.ssh`, tokens, `process.env`), **network-target** (unknown URLs
or IPs; information only).

**Repo configuration findings** table (unpinned actions, base images, Dockerfile installs, workflow
risks): the lines around the finding are read and checked:

| Check | Verdict |
|---|---|
| Action published by GitHub (`actions/*`, `github/*`) | harmless |
| Action by anyone else on a tag/branch | risky |
| Base image with no tag or `latest`, or a user's image | risky |
| Official / vendor image with a version tag | harmless |
| `npm install` of app dependencies, `curl \| sh`, `ADD https://…` | risky |
| `npm install -g <tool>` | harmless |
| `pull_request_target` that checks out the PR's code | malicious |
| other workflow risks | risky |

**Verdicts**: malicious / risky / harmless (/ needs review for packages). Findings the checks rate
harmless keep that verdict; the rest go to the AI, which confirms or corrects it with file:line
citations (see section 17). A known-malware advisory (OSV `MAL-…`) always means malicious.

**Not investigated (repo-wide rule facts)**: the 2 "no lockfile" findings. They describe the whole
project, so there is nothing to inspect. Fix: commit a `package-lock.json`.

Where this goes next: **malicious** and **risky** items become rows in Prioritized risks; **harmless**
stays here.

---

## 13. Tab: Prioritized risks

**One ranked list**, one row per package (or config finding), so you know what to fix first.

### The formula (shown on every row)

**score = min(10, CVSS × U × D × P × E × R)**

| Factor | Question | Values |
|---|---|---|
| CVSS | How bad is the flaw? | the package's **highest** CVSS. No score: advisory label (critical 9, high 7.5, medium 5, low 2). Nothing: 5.0 |
| U usage | Does it ship? | production 1.0, dev-only 0.5 |
| D depth | Listed directly? | direct 1.0, transitive 0.8 |
| P platform | Installed everywhere? | optional or OS/CPU-specific 0.6, else 1.0 |
| E exploitation | Attacked in the wild? | on CISA KEV, or EPSS ≥ 0.1 → 1.3, else 1.0 |
| R reachability | Does the app use the vulnerable code? | Reachable 1.0, Unknown 1.0, Not reachable 0.7 |

Example: lodash 2.4.2 = min(10, 9.1 × 1.0 × 0.8 × 1.0 × 1.3 × 1.0) = **9.5 critical** (critical CVE,
pulled in by sanitize-html, EPSS 20%).

**Rows from Investigate** (no CVE needed):
- malicious → **10**, always first
- risky package with no CVE → "supply-chain risk" row: **6.0 × U × D × P** (e.g. `@parcel/watcher`
  production transitive = 6.0 × 0.8 = 4.8 medium; `cypress` dev direct = 6.0 × 0.5 = 3.0 low)
- risky config finding → **6.0** (U, D, P are 1.0: it is the repo itself) → medium
- risky package that also has CVEs → keeps its CVE row, but never below **4.0** (medium)

**Bands**: critical ≥ 9, high ≥ 7, medium ≥ 4, low < 4.
**Order**: band, then Reachable → Unknown → Not reachable, then score.
**Never lowered by R**: anything critical before R, on CISA KEV, or known malware.

### Columns and labels

- **#** rank; **Score** band + score and confidence (high, or medium when EPSS is missing or CVSS came
  from a label).
- **Package**: name@version (or file:line for config), `direct` or `via <package you control>`.
- **Reachability**: Reachable / Unknown / Not reachable, with how it was decided. The AI is asked only
  for production high/medium packages (top 15) that the app's own code imports, 5 per call.
  "Not reachable" without cited proof is turned into Unknown.
- **Formula**: the exact numbers, with U/D/P/E/R chips (hover for their meaning).
- **Signals**: CISA KEV, EPSS %, labels: `known malware`, `no fix: needs review`, `supply-chain risk`,
  `repo config`, `investigation: risky`, `needs human review`.
- **Advisories**: the IDs. Click a row for the path, the AI's reason, the cited code and every advisory.
- **Header**: band tiles (click to filter), reachability counts, CISA KEV and EPSS feed status.

### Juice Shop totals

22 vulnerable packages + 5 risky packages (no CVE) + risky config findings. With the current rules
(config findings rated harmless by the checks keep that verdict), about **34 rows: critical 2,
high 6, medium 17, low 9**. Older scans made before that rule showed 42 rows, because the AI marked
15 of 16 config findings risky.

---

## 14. Tab: Fixes & approval

One **fix card** per change, for **every** risk band (critical to low), in priority order: upgrades for
known vulnerabilities, pin-and-review cards for risky packages, and config fixes.

**Each card**

- **Title**: the change, e.g. "Upgrade sanitize-html 1.4.2 → 2.18.0".
- **Scores (top right)**: every package the change fixes, each with the same score as on Prioritized
  risks, before → after. Example: upgrading sanitize-html fixes `sanitize-html 1.4.2  7.5 → 0.0` and
  `lodash 2.4.2  9.5 → 0.0`, because the new sanitize-html no longer pulls in the old lodash.
- **Explanation**: 2 to 3 plain sentences: what is wrong, what the change does, what might break.
  "AI explanation" when written by the AI (and checked), "Explanation" when generated from the rules.
- **Approve / Reject**: **Approve applies the change to the fixed copy of the app** (one copy per scan,
  branch `fix/guardian`; the scanned original is never touched). Fixes add up: each Approve goes on top of
  the earlier ones, and a later fix never lowers a version an earlier fix raised. Reject leaves it out.
  The card then shows its status: ✅ Applied, ✅ Already covered (an earlier fix did it), ❌ Couldn't
  apply (with the reason), Needs a manual change (replace/remove cards), ↩ Rolled back (it broke the build
  or the app), ⚠️ Applied, still present (the rescan still finds it, e.g. another route pulls it in).
- **Test this fix alone** (optional link): builds and rescans just this fix on its own branch.
- **Show details**: the exact change and `package.json` / file diff, packages fixed together, risk
  reduction (advisories and CVEs removed, what is still open), rollback, version jump
  (patch / minor / major), the AI's breaking-change notes and the app code that uses the package.

**How the fix version is chosen**: every route that pulls in the vulnerable version is followed (not just the
shortest), and for each route the lowest version of the package you control that brings a fixed version is
picked, **after checking with OSV that the new versions have no known high or critical advisory** (versions
that would introduce one are skipped, and the card says which). If any route has no safe version, the card
uses an npm `overrides` pin instead.

**npm compatibility check**: during the scan every package fix is tried on its own with an npm dry run
(`npm install --package-lock-only --ignore-scripts` on a temporary copy: nothing installed, no scripts).
A card npm cannot install shows "npm cannot install this fix…" with npm's reason, and Approve is disabled.
On **Approve**, the same dry run is done against the fixed copy with all earlier fixes in it: if npm cannot
combine them, the fix is not applied and the card shows **❌ Conflicts with <fix>** and npm's reason.

**Card colour** follows the card's status: green applied, amber applied but still present, red couldn't
apply or rolled back, blue applying or manual, grey rejected. "✓ Approved" itself is neutral.

**Card types (actions)**

| Action | When | What it changes |
|---|---|---|
| upgrade | the vulnerable package is direct | its version in `package.json` |
| upgrade-parent | it is pulled in by a package you list | that package's version (lowest one that brings a safe version) |
| upgrade-all | the vulnerable version is pulled in by **several** of your packages | one change per route, all in one card, so every path is fixed |
| relock | your package already allows a safe version | only the lockfile (`npm update <pkg>`) |
| override | no version of your package brings a safe one | pins it with npm `overrides` |
| pin | risky package, no CVE | pins the exact reviewed version with `overrides` and flags it for review (risk frozen, not removed) |
| config | risky workflow/Dockerfile finding | pin action to a commit SHA, pin image digest, `npm ci`, or fix trigger/permissions |
| replace | no fixed version exists (e.g. marsdb) | needs a person: replace or limit use (Approve is disabled) |
| remove | known malware | needs a person: remove it and whatever depends on it |

---

## 15. Tab: Fixed app & report

### The fixed application

Every approved fix is already applied to one copy of the project. **Build, run & verify fixed app** then:

1. **relock**: regenerates `package-lock.json` for all the applied fixes (no scripts run);
2. **build**: in Docker, `npm ci` and `npm run build` (network on for downloads such as Google Fonts);
3. **app check**: starts the app inside the sandbox (network off) and requests `GET /` on port 3000:
   "App check in the sandbox: GET / → HTTP 200" plus the end of the app's log;
4. **tests**: `npm test` with the network off. If the sandbox stops them (they need Chrome or a database,
   no network, out of memory) that is reported as "not run", not as a failure;
5. **rollback if needed**: if npm cannot resolve the tree, or the build or app breaks, the most recent
   package fix is undone (its card shows ↩ Rolled back with the log) and the rest is tried again
   (up to 3 times);
6. **rescan** of the fixed copy with the same agents, and the comparison below;
7. **run it for you**: the fixed app is started in Docker and published on **http://localhost:3001**.
   **Open app** opens it in your browser; **Stop app** stops it.

**Result badge**: ✅ Fixed app runs, ⚠️ Built, app not confirmed, ❌ Build failed. A note appears if more
fixes were approved after the last build ("build again to include them").

**Original vs fixed**: advisories per severity, total advisories, suspicious findings and package counts,
before and after. **Removed**: every advisory that is gone. **Still there, and why**: every advisory that
remains, with its reason: "no fixed version has been published" (e.g. marsdb), "fix rejected", "fix not
approved yet", "fix applied, but another route still pulls in this version", "needs a manual change", or
"new: brought in by one of the upgrades". Nothing is hidden: Juice Shop is deliberately vulnerable and some
packages have no fix.

**Download the fix as a patch**: the exact changes (package.json, lockfiles, Dockerfile, workflows) as a
git patch you can apply to the real repository.

### Report

- **Summary**: written by the AI only from the verified numbers (any other number is rejected), or a
  rule-generated sentence.
- **Remaining risk**: open, rejected, accepted (low band or not reachable), awaiting decision, resolved.
- **Audit trail**: for every card: finding (score) → decision (when) → its status in the fixed app.
- **Report (Markdown) / JSON**: the full report, including the fixed-app section (advisories before → after,
  whether the app runs, removed and remaining advisories with reasons).

### Single-fix tests (optional)

Fixes tested alone with **Test this fix alone** appear here with their own steps and logs.

## 16. How the numbers connect across tabs

| Number | Where | Why it differs from another tab |
|---|---|---|
| 1657 components vs 1660 graph nodes | Overview / Dependency graph | the graph adds the repo and its 2 projects |
| 57 advisories vs 22 packages | Vulnerabilities | one package can have several advisories |
| 34 suspicious vs 32 investigated | Suspicious changes / Investigation | 2 "no lockfile" findings are repo-wide facts with nothing to inspect |
| 16 packages investigated vs 14 + 2 findings | Investigation | 14 install-script + 2 typosquat findings, one package each |
| 91 evidence bundles | Evidence report | 57 advisories + 34 suspicious findings |
| Evidence report "initial risk" vs Prioritized bands | Evidence / Prioritized | initial risk is per advisory and simple; Prioritized is one row per package with the full formula |
| Prioritized rows (≈34) | Prioritized risks | 22 CVE packages + 5 risky packages + risky config findings |
| Fix cards | Fixes & approval | one per change for every band (critical to low) + one per supply-chain/config row; changes that fix several packages are merged into one card |

---

## 17. Facts, AI inference and the Validator

- **Fact**: read directly from a file or a tool's output (lockfile, OSV-Scanner, git, the registry).
- **Indicator**: a rule-based guess for a person to check (typosquat lookalikes).
- **AI inference**: the AI's judgement. Used only for: Investigate verdicts, the reachability label,
  fix explanations and breaking-change notes, the failed-build explanation, and the report summary.
  **The AI never sets a CVSS score, a fixed version or a package version.**
- **The Validator** (plain code) checks every AI answer before it is used: the cited files and lines
  were really shown to it and exist, quotes match the line, values are in range (verdict words,
  confidence 0 to 1), no invented advisory IDs or numbers, and no contradiction of tool facts (e.g. a
  `MAL-` advisory forces "malicious"). A failed answer is asked again once; if it fails again the rule
  result is used and the item says so.
- **Cost control**: 5 items per AI call, answers cached per package version (a rescan costs nothing),
  at most one automatic retry.
- **Banners**: each AI-using tab says whether the AI ran ("AI (model) … answered N of M") or
  "AI explanation unavailable" (no key), so AI text is never mistaken for a tool fact.

---

## 18. Glossary

| Term | Meaning |
|---|---|
| Direct / transitive | listed in your `package.json` / pulled in by another package |
| Lockfile | file pinning the exact version of every package (`package-lock.json`) |
| SBOM | Software Bill of Materials: the list of everything inside the software |
| CycloneDX | the SBOM standard used |
| CVE / GHSA | public IDs for known vulnerabilities (MITRE/NVD, GitHub) |
| OSV | Google's vulnerability database that OSV-Scanner queries |
| CVSS | 0 to 10 severity score of a vulnerability |
| EPSS | probability that a vulnerability will be exploited in the next 30 days |
| CISA KEV | US list of vulnerabilities known to be exploited |
| Install script | code a package runs automatically when installed |
| Typosquat | a malicious package named like a popular one |
| SHA pinning | referring to a GitHub Action by its exact commit, which cannot change |
| Digest | the exact content hash of a container image |
| `overrides` | npm setting that forces a specific version of a transitive package |
| Reachability | whether the app's own code actually uses the vulnerable part |
| Sandbox | an isolated Docker container with no network or secrets, used for build/test |
