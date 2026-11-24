import re
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from typing import Literal

from pydantic import BaseModel, Field

from . import db, fixed_app, llm, pipeline, report, validate
from .agents.checkout import GITHUB_URL

app = FastAPI(title="Software Supply Chain Guardian")


class ScanRequest(BaseModel):
    repo_url: str


@app.post("/api/scans", status_code=202)
def create_scan(req: ScanRequest, bg: BackgroundTasks):
    url = req.repo_url.strip()
    if not GITHUB_URL.match(url):
        raise HTTPException(400, "Enter a public GitHub URL like https://github.com/owner/repo")
    scan_id = db.create(url)
    bg.add_task(pipeline.run, scan_id, url)
    return {"id": scan_id}


@app.get("/api/scans")
def list_scans():
    return db.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = db.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan["decisions"] = db.decisions(scan_id)  # kept apart from the immutable scan record
    scan["validations"] = db.validations(scan_id)
    scan["llm"] = llm.status()
    return scan


class Decision(BaseModel):
    card_id: str
    decision: Literal["approved", "rejected"]
    decided_by: str = Field(default="reviewer", max_length=80)
    note: str = Field(default="", max_length=1000)


@app.post("/api/scans/{scan_id}/decisions")
def decide(scan_id: str, d: Decision, bg: BackgroundTasks):
    """Human Approval: record who approved or rejected a fix card, when, and why."""
    scan = db.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    cards = {c["id"]: c for c in scan["results"].get("remediate", {}).get("cards", [])}
    if d.card_id not in cards:
        raise HTTPException(404, "Fix card not found in this scan")
    if d.decision == "approved" and (cards[d.card_id].get("compat") or {}).get("ok") is False:
        raise HTTPException(409, "npm cannot install this fix with the project's dependencies: "
                                 + cards[d.card_id]["compat"]["reason"])
    row = db.decide(scan_id, d.card_id, d.decision, d.decided_by.strip() or "reviewer", d.note.strip())
    if d.decision == "approved":  # Approve applies the fix to the scan's fixed copy of the app
        db.save_validation(scan_id, d.card_id, {"card_id": d.card_id, "status": "applying", "steps": []})
        bg.add_task(fixed_app.apply_card, scan_id, d.card_id)
    return row


@app.post("/api/scans/{scan_id}/validations/{card_id}")
def revalidate(scan_id: str, card_id: str, bg: BackgroundTasks):
    """Optional: test one approved fix alone on its own branch (fix-<card>), apart from the fixed copy."""
    if db.decisions(scan_id).get(card_id, {}).get("decision") != "approved":
        raise HTTPException(409, "Only approved fixes are validated")
    if db.validations(scan_id).get(card_id, {}).get("status") in ("queued", "running"):
        raise HTTPException(409, "This fix is already being validated")
    db.save_validation(scan_id, card_id, {"card_id": card_id, "status": "queued", "steps": []})
    bg.add_task(validate.run, scan_id, card_id)
    return {"status": "queued"}


@app.post("/api/scans/{scan_id}/fixed/build")
def build_fixed(scan_id: str, bg: BackgroundTasks):
    """Build, verify and run the fixed copy that holds every applied fix."""
    vals = db.validations(scan_id)
    if not any(v.get("status") == "applied" for v in vals.values()):
        raise HTTPException(409, "Approve at least one fix first (it must show 'Applied')")
    if vals.get(fixed_app.FIXED, {}).get("status") in ("queued", "running") or             any(v.get("status") in ("applying", "checking") for v in vals.values()):
        raise HTTPException(409, "Still busy: wait for the current step to finish")
    db.save_validation(scan_id, fixed_app.FIXED, {"card_id": fixed_app.FIXED, "status": "queued", "steps": []})
    bg.add_task(fixed_app.build, scan_id)
    return {"status": "queued"}


@app.post("/api/scans/{scan_id}/fixed/stop")
def stop_fixed_app(scan_id: str):
    return {"stopped": fixed_app.stop_app(scan_id)}


@app.get("/api/scans/{scan_id}/fixed/app")
def fixed_app_status(scan_id: str):
    return fixed_app.app_status(scan_id)


@app.delete("/api/scans/{scan_id}/validations/{card_id}")
def cancel_validation(scan_id: str, card_id: str):
    """Cancel a queued validation, or stop a running one before its next step."""
    v = db.validations(scan_id).get(card_id)
    if not v or v.get("status") not in ("queued", "running"):
        raise HTTPException(409, "This validation is not queued or running")
    validate.CANCELLED.add((scan_id, card_id))
    if v["status"] == "queued":
        db.save_validation(scan_id, card_id, {**v, "status": "cancelled", "reason": "Cancelled before it started"})
    return {"status": "cancelling" if v["status"] == "running" else "cancelled"}


@app.get("/api/scans/{scan_id}/report")
def final_report(scan_id: str, format: Literal["json", "md"] = "json"):
    """Agent 14: before/after, remaining risk, audit trail, summary. ?format=md downloads Markdown."""
    if not db.get(scan_id):
        raise HTTPException(404, "Scan not found")
    rep = report.build(scan_id)
    if format == "md":
        return PlainTextResponse(report.markdown(rep), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="{scan_id}-final-report.md"'})
    return rep


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    """Stop a running scan. The agent that is working finishes its current step (e.g. an npm
    resolve), then the scan stops before the next agent and is marked cancelled."""
    scan = db.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan_id in pipeline.RUNNING:
        pipeline.CANCELLED.add(scan_id)
        db.update(scan_id, lambda d: d.update(status="cancelling"))
        return {"status": "cancelling"}
    if scan["status"] in ("queued", "running", "cancelling"):  # stale record: nothing is executing it
        db.update(scan_id, lambda d: d.update(status="cancelled", error="Stopped by user"))
        return {"status": "cancelled"}
    return {"status": scan["status"]}


@app.delete("/api/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str):
    """Remove a scan: its DB rows, its evidence folder and the cloned repo."""
    if not re.fullmatch(r"[0-9a-f]{12}", scan_id):  # ids are generated hex; also blocks path tricks
        raise HTTPException(404, "Scan not found")
    scan = db.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan_id in pipeline.RUNNING:
        raise HTTPException(409, "Scan is still running: stop it first, then delete it")
    if any(v.get("status") in ("queued", "running") for v in db.validations(scan_id).values()):
        raise HTTPException(409, "A fix is being validated: wait for it to finish, then delete the scan")
    fixed_app.stop_app(scan_id)
    db.delete(scan_id)
    for folder in (db.DATA / "workspaces" / scan_id, db.DATA / "scans" / scan_id):
        if folder.exists():
            validate._rmtree(folder)


@app.get("/api/scans/{scan_id}/artifacts/{name:path}")
def get_artifact(scan_id: str, name: str):
    """Evidence files (SBOM, generated lockfiles, tool outputs) for download."""
    base = (db.DATA / "scans" / scan_id).resolve()
    path = (base / name).resolve()
    if not path.is_relative_to(base) or not path.is_file():  # sub-folders allowed (fix logs, patch)
        raise HTTPException(404, "Artifact not found")
    return FileResponse(path, filename=f"{scan_id}-{name}")


# Serve the built dashboard (npm run build) from the same port when present.
_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=_dist, html=True), name="dashboard")
