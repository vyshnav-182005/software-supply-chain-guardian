"""Guardian orchestrator: a LangGraph workflow running each agent in turn.

Every agent is `run(state) -> (state_update, public_result)`. The wrapper records
status/timing in the DB so the dashboard can show live per-agent progress, and
stores `public_result` under results[<agent>]. A failed agent stops the scan and
marks it failed (never a clean report from a partial scan).
"""
import shutil
import time
import traceback
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from . import db
from .agents import (approval, change_detection, checkout, discovery, evidence, graph, inspection, investigate,
                     prioritize, remediate, sbom, vulnerability)


class ScanState(TypedDict, total=False):
    scan_id: str
    repo_url: str
    repo_name: str
    workdir: str
    artifacts: str
    commit_sha: str
    projects: list
    components: list
    edges: list
    paths: dict
    vulnerabilities: list
    suspicious: list
    inspection: dict
    investigations: list
    risks: list
    fixes: list


# Agents run in this order; each sees the state the earlier ones produced.
STEPS = [
    ("checkout", checkout.run),
    ("discovery", discovery.run),
    ("sbom", sbom.run),
    ("graph", graph.run),
    ("inspection", inspection.run),
    ("vulnerability", vulnerability.run),
    ("change_detection", change_detection.run),
    ("evidence", evidence.run),
    # Day 2
    ("investigate", investigate.run),
    ("prioritize", prioritize.run),
    ("remediate", remediate.run),
    ("approval", approval.run),
]


RUNNING: set[str] = set()     # scans executing in this server process
CANCELLED: set[str] = set()   # scans asked to stop; checked before each agent starts


class ScanCancelled(Exception):
    pass


def _node(key, fn):
    def run(state: ScanState) -> dict:
        sid = state["scan_id"]
        if sid in CANCELLED:
            raise ScanCancelled("Stopped by user")
        start = time.time()
        db.update(sid, lambda d: d["agents"][key].update(status="running", started_at=start))
        try:
            update, public = fn(state)
        except Exception as e:
            traceback.print_exc()
            msg = str(e)
            db.update(sid, lambda d: d["agents"][key].update(
                status="failed", error=msg, duration=round(time.time() - start, 2)))
            raise

        def save(d):
            d["agents"][key].update(
                status=public.pop("_status", "done"), summary=public.pop("_summary", ""),
                duration=round(time.time() - start, 2))
            d["results"][key] = public
            d["commit_sha"] = update.get("commit_sha", d["commit_sha"])
        db.update(sid, save)
        return update
    return run


def _build():
    g = StateGraph(ScanState)
    prev = START
    for key, fn in STEPS:
        g.add_node(key, _node(key, fn))
        g.add_edge(prev, key)
        prev = key
    g.add_edge(prev, END)
    return g.compile()


GRAPH = _build()


def run(scan_id: str, repo_url: str) -> None:
    workspace = db.DATA / "workspaces" / scan_id
    artifacts = db.DATA / "scans" / scan_id
    shutil.rmtree(workspace, ignore_errors=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    RUNNING.add(scan_id)
    db.update(scan_id, lambda d: d.update(status="running"))
    try:
        GRAPH.invoke({"scan_id": scan_id, "repo_url": repo_url,
                      "workdir": str(workspace / "repo"), "artifacts": str(artifacts)})
        db.update(scan_id, lambda d: d.update(status="completed"))
    except Exception as e:
        cancelled, msg = isinstance(e, ScanCancelled), str(e)

        def fail(d):
            d.update(status="cancelled" if cancelled else "failed", error=msg)
            for a in d["agents"].values():
                if a["status"] in ("pending", "running"):
                    a["status"] = "skipped"
        db.update(scan_id, fail)
    finally:
        RUNNING.discard(scan_id)
        CANCELLED.discard(scan_id)
