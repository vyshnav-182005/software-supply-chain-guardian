import { useEffect, useState } from 'react'
import type { FixCard, Validation } from './types'
import { artifactUrl } from './types'

export const VSTATUS: Record<string, { label: string; cls: string }> = {
  queued: { label: 'Queued', cls: 'unrated' },
  running: { label: 'Validating…', cls: 'unrated' },
  verified: { label: '✅ Verified', cls: 'low' },
  fixed_app_runs: { label: '✅ Fixed, app runs (tests not run)', cls: 'low' },
  fixed_untested: { label: '⚠️ Fixed, not tested', cls: 'medium' },
  fixed_tests_failed: { label: '⚠️ Fixed, tests failed', cls: 'medium' },
  not_fixed: { label: '❌ Not fixed / new risk', cls: 'critical' },
  manual: { label: 'Needs a manual change', cls: 'unrated' },
  error: { label: 'Validation error', cls: 'critical' },
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

export default function ValidationTab({ scanId, cards, validations, onRerun }: {
  scanId: string; cards: FixCard[]; validations: Record<string, Validation>; onRerun: () => void
}) {
  const [rep, setRep] = useState<Report | null>(null)
  const [err, setErr] = useState('')
  const key = JSON.stringify(Object.values(validations).map((v) => [v.card_id, v.status]))
  useEffect(() => {
    fetch(`/api/scans/${scanId}/report`).then((r) => (r.ok ? r.json() : Promise.reject(r.statusText)))
      .then(setRep).catch((e) => setErr(String(e)))
  }, [scanId, key])

  async function cancel(cardIds: string[]) {
    for (const id of cardIds) await fetch(`/api/scans/${scanId}/validations/${id}`, { method: 'DELETE' }).catch(() => null)
    onRerun()
  }
  const queued = Object.values(validations).filter((v) => v.status === 'queued').map((v) => v.card_id)

  const combined = validations.combined
  async function runCombined() {
    const r = await fetch(`/api/scans/${scanId}/combined`, { method: 'POST' }).catch(() => null)
    if (!r?.ok) return setErr(r ? (await r.json()).detail : 'Backend not reachable')
    onRerun()
  }

  async function rerun(cardId: string) {
    const r = await fetch(`/api/scans/${scanId}/validations/${cardId}`, { method: 'POST' }).catch(() => null)
    if (!r?.ok) return setErr(r ? (await r.json()).detail : 'Backend not reachable')
    onRerun()
  }

  const f = rep?.facts
  return (
    <div className="day2">
      {rep && (
        <section className="card">
          <div className="row-between">
            <h2>Summary</h2>
            <div className="btn-row">
              <a className="button" href={`/api/scans/${scanId}/report?format=md`}>Report (Markdown)</a>
              <a className="button secondary" href={`/api/scans/${scanId}/report`} target="_blank" rel="noreferrer">JSON</a>
            </div>
          </div>
          <div className="explain"><div className="explain-label">{rep.summary.source}</div><p>{rep.summary.text}</p></div>
          <table className="table compact">
            <thead><tr><th>Risk band</th><th>Before</th><th>After</th></tr></thead>
            <tbody>{Object.keys(f!.risk_bands_before).map((b) => (
              <tr key={b}><td><span className={`sev ${b}`}>{b}</span></td><td>{f!.risk_bands_before[b]}</td><td>{f!.risk_bands_after[b]}</td></tr>
            ))}</tbody>
          </table>
          <p className="small muted">"After" counts what is still open, rejected, accepted or awaiting a decision; only fixes
            with a ✅ Verified result are subtracted. {f!.approved} approved · {f!.rejected} rejected · {f!.awaiting_decision} awaiting decision.</p>
        </section>
      )}
      {err && <div className="alert">{err}</div>}

      <section className="card">
        <div className="row-between">
          <h2>All approved fixes together</h2>
          {combined?.status === 'queued' || combined?.status === 'running'
            ? <button className="link" onClick={() => cancel(['combined'])}>Stop after the current step</button>
            : <button onClick={runCombined}>{combined ? 'Run again' : 'Validate all approved fixes together'}</button>}
        </div>
        <p className="small muted">Applies every approved fix on one branch (<span className="mono">fix/combined</span>), resolving shared
          parents to the highest safe version, then relocks, builds, starts the app, runs the tests and rescans once. This is
          the proof that the fixes work together and the application still runs.</p>
        {combined && <CombinedResult v={combined} scanId={scanId} />}
      </section>

      <section className="card">
        <div className="row-between">
          <h2>Validation of approved fixes</h2>
          {queued.length > 0 && <button className="link" onClick={() => cancel(queued)}>Cancel all {queued.length} queued</button>}
        </div>
        <p className="small muted">Fixes are validated one at a time, in the order they were approved.</p>
        {Object.keys(validations).length === 0 && <p className="muted">No fix has been approved yet. Approve a card on the Fixes &amp; approval tab to start its validation.</p>}
        {cards.filter((c) => validations[c.id]).map((c) => {
          const v = validations[c.id]
          return (
            <div key={c.id} className="vcard">
              <div className="row-between"><b>{c.title}</b><ValidationBadge v={v} /></div>
              {v.reason && <p className="small">{v.reason}</p>}
              {v.branch && <p className="small muted mono">branch {v.branch} · {v.workspace}</p>}
              <ol className="vsteps">
                {(v.steps ?? []).map((s) => (
                  <li key={s.name} className={s.status}>
                    <b>{s.name.replace('_', ' / ')}</b> <span className="chip">{s.status}</span>{s.mode && <span className="chip">{s.mode}</span>}
                    <span className="small"> {s.detail}</span>
                    {s.log && <a className="small" href={artifactUrl(scanId, `fix-${c.id}/${s.log}`)}> log</a>}
                    {s.diff && <pre className="code diff">{s.diff}</pre>}
                  </li>
                ))}
              </ol>
              {v.comparison && (
                <div className="small">
                  <b>Before → after:</b> advisories {v.comparison.advisories_before} → {v.comparison.advisories_after};
                  packages added {v.comparison.sbom_diff.added.length}, removed {v.comparison.sbom_diff.removed.length},
                  changed {v.comparison.sbom_diff.changed.length}
                  {v.comparison.sbom_diff.changed.length > 0 && <div className="mono muted">{v.comparison.sbom_diff.changed.slice(0, 8).join(' · ')}</div>}
                  {v.comparison.new_advisories.length > 0 && <div className="note">New advisories: {v.comparison.new_advisories.map((a) => `${a.package} ${a.id} (${a.severity})`).join(', ')}</div>}
                </div>
              )}
              {v.ai?.ok && <div className="explain"><div className="explain-label">AI: why the build/tests failed</div><p>{v.ai.answer?.explanation}</p></div>}
              {v.status === 'queued' || v.status === 'running'
                ? <button className="link" onClick={() => cancel([c.id])}>{v.status === 'queued' ? 'Cancel' : 'Stop after the current step'}</button>
                : <button className="link" onClick={() => rerun(c.id)}>Run validation again</button>}
            </div>
          )
        })}
      </section>

      {rep && (
        <section className="card">
          <h2>Remaining risk</h2>
          {Object.entries(rep.remaining).map(([k, rows]) => (
            <div key={k} className="small"><b>{k.replace('_', ' ')}</b> ({rows.length}): <span className="mono">{rows.slice(0, 20).map((r) => `${r.package} (${r.score})`).join(', ')}</span></div>
          ))}
          <h2 className="section-title">Audit trail</h2>
          <table className="table compact">
            <thead><tr><th>Fix</th><th>Finding</th><th>Decision</th><th>Validation</th></tr></thead>
            <tbody>{rep.audit_trail.map((t) => (
              <tr key={t.card_id}>
                <td className="small">{t.fix}</td>
                <td className="small mono">{t.finding.package} · {t.finding.band} {t.finding.score}</td>
                <td className="small">{t.decision ? `${t.decision.decision} by ${t.decision.by}, ${new Date(t.decision.at).toLocaleString()}` : 'awaiting'}</td>
                <td className="small">{t.validation ? `${t.validation.status}: ${t.validation.rescan ?? t.validation.reason ?? ''}` : '—'}</td>
              </tr>
            ))}</tbody>
          </table>
        </section>
      )}
    </div>
  )
}

function CombinedResult({ v, scanId }: { v: Validation; scanId: string }) {
  const c: any = v.comparison
  const smoke = v.build?.smoke
  return (
    <div className="vcard">
      <div className="row-between"><b>{v.card_title ?? 'Combined fixes'}</b><ValidationBadge v={v} /></div>
      {v.reason && <p className="small">{v.reason}</p>}
      {smoke && smoke.status !== 'not_applicable' && (
        <div className={`app-run ${smoke.status === 'passed' ? 'ok' : 'bad'}`}>
          <b>{smoke.status === 'passed' ? `App runs ✅  GET / → HTTP ${smoke.http_status}` : `App: ${smoke.status}`}</b>
          <span className="small"> {smoke.detail}</span>
          {smoke.log_excerpt && <pre className="code">{smoke.log_excerpt}</pre>}
        </div>
      )}
      <ol className="vsteps">
        {(v.steps ?? []).map((s) => (
          <li key={s.name} className={s.status}>
            <b>{s.name.replaceAll('_', ' ')}</b> <span className="chip">{s.status}</span>{s.mode && <span className="chip">{s.mode}</span>}
            <span className="small"> {s.detail}</span>
            {s.log && <a className="small" href={artifactUrl(scanId, `fix-combined/${s.log}`)}> log</a>}
          </li>
        ))}
      </ol>
      {!!v.not_applied?.length && <p className="small note">Not applied automatically: {v.not_applied.map((x) => `${x.fix} (${x.why})`).join('; ')}</p>}
      {c?.remaining && (
        <>
          <table className="table compact">
            <thead><tr><th></th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total advisories</th></tr></thead>
            <tbody>
              <tr><td>Before</td>{['critical', 'high', 'medium', 'low'].map((k) => <td key={k}>{c.severity_before[k]}</td>)}<td><b>{c.advisories_before}</b></td></tr>
              <tr><td>After</td>{['critical', 'high', 'medium', 'low'].map((k) => <td key={k}>{c.severity_after[k]}</td>)}<td><b>{c.advisories_after}</b></td></tr>
            </tbody>
          </table>
          <h3>What is still there, and why ({c.remaining.length})</h3>
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
