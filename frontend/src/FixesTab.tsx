import { useState } from 'react'
import type { Decision, FixCard, Results, Risk, Validation } from './types'
import { ValidationBadge } from './ValidationTab'
import { AiNote, Snippets } from './Day2Common'

type Pkg = NonNullable<FixCard['packages']>[number]

/** Packages a card fixes, with the same score as on Prioritized risks. Cards from scans made before
 *  per-package scores existed only list "also_fixes", so their scores are looked up in the ranking. */
function packagesOf(c: FixCard, risks: Risk[]): Pkg[] {
  if (c.packages?.length) return c.packages
  const find = (name: string, version: string) => risks.find((r) => r.package === name && r.version === version)
  const ids = [`${c.package}@${c.version}`, ...(c.also_fixes ?? [])]
  const list = ids.map((id) => {
    const at = id.lastIndexOf('@')
    const [name, version] = [id.slice(0, at), id.slice(at + 1)]
    const r = find(name, version)
    return { package: name, version, band: r?.band ?? c.band, score_before: r?.final_score ?? c.score_before, score_after: 0 }
  })
  const changed = c.change?.package
  return list.sort((a, b) => Number(a.package !== changed) - Number(b.package !== changed) || b.score_before - a.score_before)
}

export default function FixesTab({ scanId, data, decisions, onDecided, risks = [], validations = {} }: {
  scanId: string; data: NonNullable<Results['remediate']>; decisions: Record<string, Decision>; onDecided: () => void; risks?: Risk[]
  validations?: Record<string, Validation>
}) {
  const decided = Object.values(decisions)
  return (
    <div className="day2">
      <p className="small muted">
        Each card is one recommended fix. Read the explanation, then approve or reject it. <b>Approve applies the change</b> to
        the fixed copy of the app (the scanned original is untouched); then build, run and verify it on the Fixed app &amp; report tab. {decided.filter((d) => d.decision === 'approved').length} approved ·{' '}
        {decided.filter((d) => d.decision === 'rejected').length} rejected · {data.cards.length - decided.length} waiting
      </p>
      {data.errors.length > 0 && <div className="alert">Could not plan a fix for: {data.errors.map((e) => `${e.package} (${e.error})`).join('; ')}</div>}
      {data.cards.map((c) => <Card key={c.id} c={c} pkgs={packagesOf(c, risks)} scanId={scanId} decision={decisions[c.id]} validation={validations[c.id]} onDecided={onDecided} />)}
      {data.cards.length === 0 && <div className="card muted">No critical or high risks to fix.</div>}
    </div>
  )
}

function Card({ c, pkgs, scanId, decision, validation, onDecided }: { c: FixCard; pkgs: Pkg[]; scanId: string; decision?: Decision; validation?: Validation; onDecided: () => void }) {
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(false)
  const ch = c.change
  const ai = c.ai.ok ? c.ai.answer! : null

  async function decide(d: 'approved' | 'rejected') {
    setBusy(true)
    setErr('')
    const r = await fetch(`/api/scans/${scanId}/decisions`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ card_id: c.id, decision: d }),
    }).catch(() => null)
    setBusy(false)
    if (!r?.ok) return setErr(r ? (await r.json()).detail?.toString() ?? 'Failed' : 'Backend not reachable')
    onDecided()
  }

  return (
    <section className={`card fixcard ${decision?.decision === 'rejected' ? 'rejected' : ''} ${validation ? `v-${validation.status}` : ''}`}>
      <div className="fix-head">
        <h2>{c.title}</h2>
        <div className="score-move" title="Risk score from Prioritized risks, before → after this fix">
          {pkgs.map((p) => (
            <div key={p.package + p.version}>
              <span className="mono small">{p.package} {p.version}</span>{' '}
              <span className={`sev ${p.band}`}>{p.score_before.toFixed(1)}</span> → <span className="sev low">{p.score_after.toFixed(1)}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="explain">
        <div className="explain-label">{c.plain?.source === 'AI' ? 'AI explanation' : 'Explanation'}</div>
        <p>{c.plain?.text ?? ai?.summary ?? c.title}</p>
      </div>

      <div className="decision">
        {decision ? (
          <div className={`decided ${decision.decision}`}>
            {decision.decision === 'approved' ? '✓ Approved' : '✕ Rejected'} · {new Date(decision.decided_at).toLocaleString()}
            {' '}<ValidationBadge v={validation} />
          </div>
        ) : (
          <>
            <button className="approve" disabled={busy || c.action === 'replace'} onClick={() => decide('approved')}>Approve</button>
            <button className="reject" disabled={busy} onClick={() => decide('rejected')}>Reject</button>
          </>
        )}
        {decision?.decision === 'approved' && ['applied', 'already_applied', 'applied_still_present'].includes(validation?.status ?? '') && (
          <button className="link" title="Optional: build and rescan this fix alone on its own branch"
                  onClick={() => fetch(`/api/scans/${scanId}/validations/${c.id}`, { method: 'POST' }).then(onDecided)}>Test this fix alone</button>
        )}
        {validation?.reason && validation.status !== 'applied' && <span className="small muted">{validation.reason}</span>}
        <button className="link details-toggle" onClick={() => setOpen(!open)}>{open ? 'Hide details' : 'Show details'}</button>
        {err && <span className="note small">{err}</span>}
      </div>

      {open && (
        <div className="fix-details">
          <div className="fix-grid">
            <div>
              <h3>Change</h3>
              {ch ? <p className="mono small">{ch.package}: {ch.from} → {ch.to} <span className="chip">{ch.jump} jump</span><br />{ch.manifest} · {ch.field}</p>
                  : <p className="small">No version change possible.</p>}
              {c.patch && <pre className="code diff">{c.patch}</pre>}
              {pkgs.length > 1 && <p className="small muted">Fixes {pkgs.map((p) => `${p.package} ${p.version}`).join(' and ')} in one change</p>}
              {(c.changes?.length ?? 0) > 1 && <ul className="small">{c.changes!.map((x, i) => <li key={i} className="mono">{x.field === 'lockfile' ? `lockfile: ${x.package} → ${x.to}` : `${x.package}: ${x.from} → ${x.to} (${x.jump})`}</li>)}</ul>}
              {(c.routes?.length ?? 0) > 1 && <p className="small muted">Routes that pull it in: {c.routes!.join(' · ')}</p>}
              {c.vetting && <p className="small muted">{c.vetting}</p>}
            </div>
            <div>
              <h3>Risk reduction</h3>
              <p className="small">Removes {c.advisories_removed.length} advisor{c.advisories_removed.length === 1 ? 'y' : 'ies'}
                {c.cves_removed.length > 0 && <> ({c.cves_removed.join(', ')})</>}.
                {c.remaining.length > 0 ? <> Still open: <span className="mono">{c.remaining.join(', ')}</span>.</> : ' Nothing left open on this package.'}</p>
              <h3>Rollback</h3>
              <p className="small">{c.rollback ? c.rollback.how : 'n/a'}</p>
            </div>
            <div>
              <h3>Compatibility <AiNote ai={c.ai} /></h3>
              <p className="small">Version jump: <b>{c.compatibility.jump ?? 'n/a'}</b>{ai && <> · breaking risk: <b>{ai.breaking_risk}</b></>}</p>
              {ai && <p className="small">{ai.summary}</p>}
              {ai && ai.notes?.length > 0 && <ul className="small">{ai.notes.map((n: any, i: number) => <li key={i}>{n.text}{n.file && <span className="mono muted"> ({n.file}:{n.line})</span>}</li>)}</ul>}
            </div>
          </div>
          <Snippets snippets={c.usage_snippets} cites={(ai?.notes ?? []).filter((n: any) => n.file)} />
        </div>
      )}
    </section>
  )
}
