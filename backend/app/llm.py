"""LLM access for the Day 2 agents, plus the shared Validator.

Provider: any OpenAI-compatible API. Defaults to Groq + Llama 3.3 70B. Settings come from
environment variables or backend/.env (gitignored):

  GROQ_API_KEY         the key (GUARDIAN_LLM_API_KEY also accepted)
  GUARDIAN_LLM_BASE_URL  default https://api.groq.com/openai/v1
  GUARDIAN_LLM_MODEL     default llama-3.3-70b-versatile

Every call goes through `ask()`:
  1. cached answer for (task, model, package@version, prompt hash)? return it
  2. call the model, JSON mode, temperature 0
  3. run the caller's validator (plain code: cited files/lines exist, ids real, values in range,
     no contradiction of tool facts); on failure retry once with the problems listed
  4. still failing, no key, or API error -> {"ok": False, ...}; the agent then keeps its rule-based
     result and marks the item "needs human review" / "AI explanation unavailable".
The pipeline never depends on the LLM to finish.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

from . import db

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
if ENV_FILE.exists():  # tiny .env loader: KEY=VALUE lines, real env vars win
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and not k.startswith("#"):
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

API_KEY = os.environ.get("GUARDIAN_LLM_API_KEY") or os.environ.get("GROQ_API_KEY")
BASE_URL = os.environ.get("GUARDIAN_LLM_BASE_URL", "https://api.groq.com/openai/v1")
MODEL = os.environ.get("GUARDIAN_LLM_MODEL", "llama-3.3-70b-versatile")

_client = None


def status() -> dict:
    return {"enabled": bool(API_KEY), "model": MODEL, "base_url": BASE_URL}


def _chat(system: str, user: str) -> tuple[str, dict]:
    global _client
    if _client is None:
        from openai import OpenAI
        # at most one automatic retry (rate limit / 5xx) so the call count stays predictable
        _client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=90, max_retries=1)
    r = _client.chat.completions.create(
        model=MODEL, temperature=0, response_format={"type": "json_object"},
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
    usage = {"prompt_tokens": r.usage.prompt_tokens, "completion_tokens": r.usage.completion_tokens} if r.usage else {}
    return r.choices[0].message.content or "", usage


def ask(task: str, subject: str, system: str, user: str, validate) -> dict:
    """validate(answer: dict) -> list of problems (empty = valid)."""
    key = f"{task}|{MODEL}|{subject}|{hashlib.sha1((system + user).encode()).hexdigest()[:16]}"
    cached = db.cache_get(key)
    if cached:
        return {**cached, "cached": True}
    if not API_KEY:
        return {"ok": False, "reason": "AI explanation unavailable: no API key configured"}
    problems, tokens = [], 0
    prompt = user
    for attempt in (1, 2):
        try:
            raw, usage = _chat(system, prompt)
            tokens += sum(usage.values())
            answer = json.loads(raw)
            problems = validate(answer) if isinstance(answer, dict) else ["answer is not a JSON object"]
        except json.JSONDecodeError:
            problems = ["answer is not valid JSON"]
        except Exception as e:  # network, auth, rate limit: keep rule result
            return {"ok": False, "reason": f"AI explanation unavailable: {type(e).__name__}: {str(e)[:200]}"}
        if not problems:
            result = {"ok": True, "answer": answer, "model": MODEL, "attempts": attempt, "tokens": tokens,
                      "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            db.cache_put(key, result)
            return result
        prompt = (user + "\n\nYour previous answer was rejected by the validator:\n- " + "\n- ".join(problems)
                  + "\nAnswer again, fixing these problems, as JSON only.")
    return {"ok": False, "reason": "needs human review: AI answer failed validation twice",
            "problems": problems, "tokens": tokens}


BATCH = 5
BATCH_RULES = """

You will receive several ITEMS, each starting with a line "ITEM id=<id>". Judge each item on its
own, using only that item's evidence. Reply with ONE JSON object:
{"answers": [{"id": "<the item id>", ...the fields described above...}, ...]}
with exactly one answer per item."""


def _key(task: str, subject: str, system: str, user: str) -> str:
    return f"{task}|{MODEL}|{subject}|{hashlib.sha1((system + user).encode()).hexdigest()[:16]}"


def _call(system: str, prompt: str) -> tuple[str, dict]:
    """One API call. On a rate limit (HTTP 429) wait as long as the API asks (max 60 s) and try once more."""
    for attempt in (1, 2):
        try:
            return _chat(system, prompt)
        except Exception as e:
            msg = str(e)
            if attempt == 1 and ("429" in msg or "rate limit" in msg.lower()):
                m = re.search(r"try again in ([\d.]+)\s*s", msg)
                time.sleep(min(60.0, float(m.group(1)) + 1 if m else 20.0))
                continue
            raise


def _answers(raw: str, items: list) -> dict:
    """answers by item id; ids compared loosely, and a single answer for a single item always matches."""
    data = json.loads(raw)
    answers = data.get("answers") if isinstance(data, dict) else None
    if answers is None and isinstance(data, dict) and len(items) == 1 and "id" not in data:
        answers = [data]  # the model answered one item without the wrapper
    answers = [a for a in answers or [] if isinstance(a, dict)]
    if len(items) == 1 and len(answers) == 1:
        return {items[0]["subject"]: answers[0]}
    norm = lambda x: re.sub(r"\s+", "", str(x)).lower()
    by = {norm(a.get("id")): a for a in answers}
    return {r["subject"]: by[norm(r["subject"])] for r in items if norm(r["subject"]) in by}


def ask_batch(task: str, system: str, requests: list[dict]) -> dict[str, dict]:
    """Like ask(), for many items at once: BATCH items per API call, cache per item. Items whose answer
    is missing or fails the Validator are asked again one at a time (with the problems listed), so one
    confusing item cannot spoil the others.
    requests: [{"subject": unique id, "user": prompt text, "validate": fn(answer) -> problems}]
    returns {subject: result}."""
    out, pending = {}, []
    for r in requests:
        cached = db.cache_get(_key(task, r["subject"], system, r["user"]))
        if cached:
            out[r["subject"]] = {**cached, "cached": True}
        elif not API_KEY:
            out[r["subject"]] = {"ok": False, "reason": "AI explanation unavailable: no API key configured"}
        else:
            pending.append(r)

    def ask_group(items: list, attempt: int, problems: dict) -> list:
        """One call for `items`; stores the valid answers, returns the items that still need an answer."""
        prompt = "\n\n".join(
            f"ITEM id={r['subject']}\n{r['user']}"
            + (("\nYour previous answer for this item was rejected by the validator:\n- "
                + "\n- ".join(problems[r["subject"]]) + "\nFix these problems.") if r["subject"] in problems else "")
            for r in items)
        try:
            raw, usage = _call(system + BATCH_RULES, prompt)
            by_id = _answers(raw, items)
        except json.JSONDecodeError:
            by_id, usage = {}, {}
        except Exception as e:
            if "json" in str(e).lower():  # the API rejected malformed JSON: a failed answer, not an outage
                by_id, usage = {}, {}
            else:  # network, auth, still rate-limited: keep the rule results
                for r in items:
                    out[r["subject"]] = {"ok": False, "reason": f"AI explanation unavailable: {type(e).__name__}: {str(e)[:200]}"}
                return []
        share, failed = sum(usage.values()) // max(1, len(items)), []
        for r in items:
            a = by_id.get(r["subject"])
            p = ["no answer was given for this item"] if a is None else r["validate"](a)
            if p:
                problems[r["subject"]] = p
                failed.append(r)
                continue
            result = {"ok": True, "answer": {k: v for k, v in a.items() if k != "id"}, "model": MODEL,
                      "attempts": attempt, "tokens": share, "batch_size": len(items),
                      "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            db.cache_put(_key(task, r["subject"], system, r["user"]), result)
            out[r["subject"]] = result
        return failed

    for start in range(0, len(pending), BATCH):
        problems: dict = {}
        failed = ask_group(pending[start:start + BATCH], 1, problems)
        for r in failed:  # second chance, alone
            if ask_group([r], 2, problems):
                out[r["subject"]] = {"ok": False, "reason": "needs human review: AI answer failed validation twice",
                                     "problems": problems.get(r["subject"], [])}
    return out


# ---------------------------------------------------------------- shared Validator checks

def check_enum(answer: dict, field: str, allowed: set) -> list:
    return [] if answer.get(field) in allowed else [f"'{field}' must be one of {sorted(allowed)}"]


def check_number(answer: dict, field: str, lo: float, hi: float) -> list:
    v = answer.get(field)
    if not isinstance(v, (int, float)) or isinstance(v, bool) or not lo <= v <= hi:
        return [f"'{field}' must be a number between {lo} and {hi}"]
    return []


def check_citations(answer: dict, field: str, files: dict[str, list[str]], required: bool = True) -> list:
    """files: {path: lines}. Every cited {"file", "line"} must exist; quotes must match that line."""
    cites = answer.get(field)
    if not isinstance(cites, list) or (required and not cites):
        return [f"'{field}' must be a non-empty list of {{file, line}} citations"] if required else []
    out = []
    for c in cites:
        if not isinstance(c, dict) or c.get("file") not in files:
            out.append(f"citation {c!r} refers to a file that was not provided")
            continue
        line, lines = c.get("line"), files[c["file"]]
        if not isinstance(line, int) or not 1 <= line <= len(lines):
            out.append(f"citation {c['file']}:{line} is outside the file (1-{len(lines)})")
        elif c.get("quote") and c["quote"].strip()[:40] not in lines[line - 1]:
            out.append(f"quote for {c['file']}:{line} does not appear on that line")
    return out


def check_ids(text: str, known_ids: set[str]) -> list:
    """Any advisory id mentioned in free text must be one the tools reported."""
    import re
    found = set(re.findall(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|MAL-\d{4}-\d+)\b", text or ""))
    unknown = found - known_ids
    return [f"mentions advisory ids not reported by the scanners: {sorted(unknown)}"] if unknown else []


def numbered(lines: list[str], start: int = 1) -> str:
    return "\n".join(f"{i:>4}| {l}" for i, l in enumerate(lines, start))
