import { useEffect, useState } from 'react'
import type { FixCard, Validation } from './types'
import { artifactUrl } from './types'

export const VSTATUS: Record<string, { label: string; cls: string }> = {
  // a fix card in the fixed copy
  applying: { label: 'Applying…', cls: 'unrated' },
  checking: { label: 'Checking the dependency tree…', cls: 'unrated' },
  conflicts: { label: '❌ Conflicts', cls: 'critical' },
  applied: { label: '✅ Applied', cls: 'low' },
  already_applied: { label: '✅ Already covered', cls: 'low' },
  applied_still_present: { label: '⚠️ Applied, still present', cls: 'medium' },
  apply_failed: { label: "❌ Couldn't apply", cls: 'critical' },
  rolled_back: { label: '↩ Rolled back', cls: 'critical' },
  manual: { label: 'Needs a manual change', cls: 'unrated' },
  // the fixed app, or an optional single-fix test
  queued: { label: 'Queued', cls: 'unrated' },
  running: { label: 'Working…', cls: 'unrated' },
  running_ok: { label: '✅ Fixed app runs', cls: 'low' },
  built: { label: '⚠️ Built, app not confirmed', cls: 'medium' },
  failed: { label: '❌ Build failed', cls: 'critical' },
  original_fails: { label: '⚠️ The original app fails too (not the fixes)', cls: 'medium' },
  verified: { label: '✅ Verified', cls: 'low' },
  fixed_app_runs: { label: '✅ Fixed, app runs (tests not run)', cls: 'low' },
  fixed_untested: { label: '⚠️ Fixed, not tested', cls: 'medium' },
  fixed_tests_failed: { label: '⚠️ Fixed, tests failed', cls: 'medium' },
  not_fixed: { label: '❌ Not fixed / new risk', cls: 'critical' },
  error: { label: 'Error', cls: 'critical' },
  cancelled: { label: 'Cancelled', cls: 'unrated' },
}

export function ValidationBadge({ v }: { v?: Validation }) {
  if (!v) return null
  const s = VSTATUS[v.status] ?? { label: v.status, cls: 'unrated' }
  return <span className={`sev ${s.cls}`} title={v.reason}>{s.label}</span>
}

type Report = {
  facts: Record<string, any>
  remaining: Record<string, { package: string; band: string; score: number }[]>
  audit_trail: any[]
  summary: { text: string; source: string }
  generated_at: string
}

const SEV = ['critical', 'high', 'medium', 'low'] as const

export default function ValidationTab({ scanId, cards, validations, onRerun }: {
  scanId: string; cards: FixCard[]; validations: Record<string, Validation>; onRerun: () => void
}) {
  const [rep, setRep] = useState<Report | null>(null)
  const [err, setErr] = useState('')
  const fixed = validations.fixed as any
  const key = JSON.stringify(Object.values(validations).map((v) => [v.card_id, v.status]))
  useEffect(() => {
    fetch(`/api/scans/${scanId}/report`).then((r) => (r.ok ? r.json() : Promise.reject(r.statusText)))
      .then(setRep).catch((e) => setErr(String(e)))
  }, [scanId, key])

  async function post(url: string) {
    setErr('')
    const r = await fetch(url, { method: 'POST' }).catch(() => null)
    if (!r?.ok) return setErr(r ? (await r.json()).detail : 'Backend not reachable')
    onRerun()
  }
  const applied = cards.filter((c) => validations[c.id]?.status === 'applied' || validations[c.id]?.status === 'applied_still_present')
  const busy = fixed?.status === 'queued' || fixed?.status === 'running'
  const singles = cards.filter((c) => validations[c.id]?.steps?.length)
  const f = rep?.facts

  return (
    <div className="day2">
      {err && <div className="alert">{err}</div>}

      <section className="card">
        <div className="row-between">
          <h2>The fixed application</h2>
          {busy ? <span className="sev unrated">Working…</span>
            : <button disabled={!applied.length} onClick={() => post(`/api/scans/${scanId}/fixed/build`)}>
                {fixed ? 'Build, run & verify again' : 'Build, run & verify fixed app'}</button>}
        </div>
        <p className="small muted">Every approved fix is applied to one copy of the project (branch <span className="mono">fix/guardian</span>;
          the scanned original is untouched). This button installs, builds and starts that fixed copy, runs the tests, rescans it,
          and leaves the fixed app running at <span className="mono">http://localhost:3001</span> for you to open. By default it
          runs on this laptop (fast, but the project's own code runs without a sandbox: use it for repos you trust);
          set <span className="mono">GUARDIAN_RUNNER=docker</span> in backend/.env to use the Docker sandbox instead. {applied.length} fix{applied.length === 1 ? '' : 'es'} applied so far.</p>
        {fixed?.outdated && <div className="note small">More fixes were applied after the last build: build again to include them.</div>}
        {fixed && <FixedResult v={fixed} scanId={scanId} onChange={onRerun} />}
      </section>

      {rep && (
        <section className="card">
          <div className="row-between">
            <h2>Report</h2>
            <div className="btn-row">
              <a className="button" href={`/api/scans/${scanId}/report?format=md`}>Report (Markdown)</a>
              <a className="button secondary" href={`/api/scans/${scanId}/report`} target="_blank" rel="noreferrer">JSON</a>
            </div>
          </div>
          <div className="explain"><div className="explain-label">{rep.summary.source}</div><p>{rep.summary.text}</p></div>
          <p className="small muted">{f!.approved} approved · {f!.rejected} rejected · {f!.awaiting_decision} awaiting a decision</p>
          {!!(rep as any).skipped_incompatible?.length && (
            <div className="small"><b>Skipped as incompatible ({(rep as any).skipped_incompatible.length}):</b>
              <ul>{(rep as any).skipped_incompatible.map((x: any) => <li key={x.fix}>{x.fix}: <span className="muted">{x.why}</span></li>)}</ul></div>
          )}
          <h3>Remaining risk</h3>
          {Object.entries(rep.remaining).map(([k, rows]) => (
            <div key={k} className="small"><b>{k.replace('_', ' ')}</b> ({rows.length}): <span className="mono">{rows.slice(0, 20).map((r) => `${r.package} (${r.score})`).join(', ')}</span></div>
          ))}
          <h3>Audit trail</h3>
          <table className="table compact">
            <thead><tr><th>Fix</th><th>Finding</th><th>Decision</th><th>Result</th></tr></thead>
            <tbody>{rep.audit_trail.map((t) => (
              <tr key={t.card_id}>
                <td className="small">{t.fix}</td>
                <td className="small mono">{t.finding.package} · {t.finding.band} {t.finding.score}</td>
                <td className="small">{t.decision ? `${t.decision.decision}, ${new Date(t.decision.at).toLocaleString()}` : 'awaiting'}</td>
                <td className="small">{t.validation ? `${VSTATUS[t.validation.status]?.label ?? t.validation.status}${t.validation.reason ? ': ' + t.validation.reason : ''}` : '—'}</td>
              </tr>
            ))}</tbody>
          </table>
        </section>
      )}

      {singles.length > 0 && (
        <section className="card">
          <h2>Single-fix tests</h2>
          <p className="small muted">Optional: one fix tested alone on its own branch, apart from the fixed application.</p>
          {singles.map((c) => {
            const v = validations[c.id]
            return (
              <div key={c.id} className="vcard">
                <div className="row-between"><b>{c.title}</b><ValidationBadge v={v} /></div>
                {v.reason && <p className="small">{v.reason}</p>}
                <Steps v={v} scanId={scanId} folder={`fix-${c.id}`} />
              </div>
            )
          })}
        </section>
      )}
    </div>
  )
}

function Steps({ v, scanId, folder }: { v: Validation; scanId: string; folder: string }) {
  return (
    <ol className="vsteps">
      {(v.steps ?? []).map((s) => (
        <li key={s.name} className={s.status}>
          <b>{s.name.replaceAll('_', ' ')}</b> <span className="chip">{s.status}</span>{s.mode && <span className="chip">{s.mode}</span>}
          <span className="small"> {s.detail}</span>
          {s.log && <a className="small" href={artifactUrl(scanId, `${folder}/${s.log}`)}> log</a>}
          {s.diff && <pre className="code diff">{s.diff}</pre>}
        </li>
      ))}
    </ol>
  )
}

function FixedResult({ v, scanId, onChange }: { v: any; scanId: string; onChange: () => void }) {
  const [app, setApp] = useState<{ running: boolean; url?: string } | null>(null)
  useEffect(() => {
    fetch(`/api/scans/${scanId}/fixed/app`).then((r) => r.json()).then(setApp).catch(() => setApp(null))
  }, [scanId, v.status, v.finished_at])
  async function stop() {
    await fetch(`/api/scans/${scanId}/fixed/stop`, { method: 'POST' }).catch(() => null)
    setApp({ running: false })
    onChange()
  }
  const c = v.comparison
  const smoke = v.build?.smoke
  return (
    <div className="vcard">
      <div className="row-between"><b>Result</b><ValidationBadge v={v} /></div>
      {v.reason && <p className="small">{v.reason}</p>}
      {app?.running && (
        <div className="app-run ok">
          <b>The fixed app is running ✅</b> <a href={app.url} target="_blank" rel="noreferrer" className="button">Open app</a>{' '}
          <button className="reject" onClick={stop}>Stop app</button>
          <div className="small mono">{app.url}</div>
        </div>
      )}
      {!app?.running && v.app && <div className="app-run bad small">{v.app.detail}</div>}
      {smoke && smoke.status && smoke.status !== 'not_applicable' && (
        <div className={`app-run ${smoke.status === 'passed' ? 'ok' : 'bad'} small`}>
          <b>{smoke.status === 'passed' ? `App check: GET / → HTTP ${smoke.http_status}` : `App check: ${smoke.status}`}</b> {smoke.detail}
          {v.build?.mode?.startsWith('local') && <div className="muted">Ran on this laptop without a sandbox (GUARDIAN_RUNNER=local).</div>}
          {smoke.log_excerpt && <pre className="code">{smoke.log_excerpt}</pre>}
        </div>
      )}
      {!!v.rollbacks?.length && <div className="note small">Rolled back: {v.rollbacks.map((r: any) => `${r.fix} (${r.why})`).join('; ')}</div>}
      <Steps v={v} scanId={scanId} folder="fixed" />
      {!!v.fixes_not_applied?.length && <p className="small muted">Approved but not in the fixed app: {v.fixes_not_applied.map((x: any) => `${x.fix} (${x.why})`).join('; ')}</p>}
      {c && (
        <>
          <h3>Original vs fixed</h3>
          <table className="table compact">
            <thead><tr><th></th>{SEV.map((s) => <th key={s}>{s}</th>)}<th>Advisories</th><th>Suspicious findings</th><th>Packages</th></tr></thead>
            <tbody>
              <tr><td>Original</td>{SEV.map((s) => <td key={s}>{c.severity_before[s]}</td>)}<td><b>{c.advisories_before}</b></td><td>{c.suspicious_before}</td><td>{c.packages_before}</td></tr>
              <tr><td>Fixed</td>{SEV.map((s) => <td key={s}>{c.severity_after[s]}</td>)}<td><b>{c.advisories_after}</b></td><td>{c.suspicious_after}</td><td>{c.packages_after}</td></tr>
            </tbody>
          </table>
          <p className="small muted">Packages: +{c.sbom_diff.added.length} added, −{c.sbom_diff.removed.length} removed or changed version.
            {v.patch && <> <a href={artifactUrl(scanId, v.patch)}>Download the fix as a patch</a> (package.json, lockfiles, Dockerfile, workflows).</>}</p>
          <details><summary className="small"><b>Removed ({c.removed.length})</b></summary>
            <p className="small mono">{c.removed.map((x: any) => `${x.package} ${x.id}`).join(' · ')}</p></details>
          <h3>Still there, and why ({c.remaining.length})</h3>
          <div className="table-wrap short">
            <table className="table compact">
              <thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Why it remains</th></tr></thead>
              <tbody>{c.remaining.map((x: any) => (
                <tr key={x.package + x.id}><td><span className={`sev ${x.severity}`}>{x.severity}</span></td>
                  <td className="mono small">{x.package}</td><td className="mono small">{x.id}</td><td className="small">{x.reason}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
