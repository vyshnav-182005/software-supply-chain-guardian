import { Fragment, useState } from 'react'
import type { ConfigItem, Results, SuspiciousFinding } from './types'
import { AiNote, CodeView, LlmBanner } from './Day2Common'

const VERDICT_CLASS: Record<string, string> = { malicious: 'critical', risky: 'high', harmless: 'low', unknown: 'unrated' }

const PACKAGE_RULES = new Set(['install-script', 'typosquat', 'unexpected-origin'])
const CONFIG_RULES = new Set(['unpinned-action', 'base-image', 'build-install', 'workflow-risk'])

export default function InvestigationTab({ data, suspicious }: { data: NonNullable<Results['investigate']>; suspicious: SuspiciousFinding[] }) {
  const [open, setOpen] = useState<string | null>(null)
  // reconcile with the Suspicious changes tab: every finding is either investigated or a repo-wide rule fact
  const pkgFindings = suspicious.filter((f) => PACKAGE_RULES.has(f.rule))
  const cfgFindings = suspicious.filter((f) => CONFIG_RULES.has(f.rule))
  const ruleFacts = suspicious.filter((f) => !PACKAGE_RULES.has(f.rule) && !CONFIG_RULES.has(f.rule))
  return (
    <div className="day2">
      <div className="reconcile small">
        <b>{suspicious.length} suspicious findings</b> = {pkgFindings.length} package findings
        ({data.items.length} packages investigated{data.not_investigated?.length ? `, ${data.not_investigated.length} over the limit of 25` : ''})
        {' '}+ {cfgFindings.length} config findings ({data.config_items?.length ?? 0} investigated)
        {' '}+ {ruleFacts.length} repo-wide rule fact{ruleFacts.length === 1 ? '' : 's'} (not investigated, see below)
      </div>
      <LlmBanner llm={data.llm} what="judged each flagged package" />
      <div className="kpis">
        {(['malicious', 'risky', 'harmless', 'unknown'] as const).map((v) => (
          <div key={v} className="kpi"><div className={`kpi-value sev-text ${VERDICT_CLASS[v]}`}>{(data.counts[v] ?? 0) + (data.config_counts?.[v] ?? 0)}</div>
            <div className="kpi-label">{v === 'unknown' ? 'needs review' : v}</div>
            <div className="kpi-hint">{data.counts[v] ?? 0} packages + {data.config_counts?.[v] ?? 0} config</div></div>
        ))}
        <div className="kpi"><div className="kpi-value">{data.items.length}</div><div className="kpi-label">Packages investigated</div></div>
        <div className="kpi"><div className="kpi-value">{data.config_items?.length ?? 0}</div><div className="kpi-label">Config findings investigated</div>
          {data.config_counts && <div className="kpi-hint">{(data.config_counts.malicious ?? 0) + (data.config_counts.risky ?? 0)} risky or worse</div>}</div>
      </div>
      <p className="small muted">
        Each package flagged by Suspicious-Change Detection (install script, typosquat lookalike, unexpected origin) or
        listed in OSV as malware is downloaded with <code>npm pack --ignore-scripts</code> (never installed or run),
        compared with the lockfile hash, and its install hooks and the files they run are checked for downloads,
        command execution, obfuscation, secret access and outbound URLs.
      </p>
      <section className="card">
        <table className="table">
          <thead><tr><th>Verdict</th><th>Package</th><th>Why flagged</th><th>Tool facts</th><th>Reason</th></tr></thead>
          <tbody>
            {data.items.map((i) => (
              <Fragment key={i.id}>
                <tr className="clickable" onClick={() => setOpen(open === i.id ? null : i.id)}>
                  <td>
                    <span className={`sev ${VERDICT_CLASS[i.verdict]}`}>{i.verdict === 'unknown' ? 'review' : i.verdict}
                      {i.confidence != null && <b>{Math.round(i.confidence * 100)}%</b>}</span>
                    <div className="small muted">{i.basis}</div>
                  </td>
                  <td className="mono small">{i.package}@{i.version}
                    <div>{i.direct ? <span className="chip direct">direct</span> : <span className="chip">transitive</span>}
                      {i.scope !== 'runtime' && <span className="chip">{i.scope}</span>}</div></td>
                  <td>{i.flagged_by.map((f) => <span key={f} className="chip">{f}</span>)}</td>
                  <td className="small">
                    <div>{i.tarball.integrity_match ? '✓ tarball matches lockfile hash' : i.tarball.error ? `✕ ${i.tarball.error}` : '✕ tarball hash differs from lockfile'}</div>
                    <div>{i.install_scripts.length ? i.install_scripts.map((h) => <div key={h.hook} className="mono">{h.hook}: {h.command}</div>) : 'no install hooks'}</div>
                    <div>Static checks: {i.static?.hits.length ? [...new Set(i.static.hits.map((h) => h.rule))].join(', ') : 'no matches'}</div>
                    {i.mal_advisories.length > 0 && <div className="note">OSV malware: {i.mal_advisories.join(', ')}</div>}
                  </td>
                  <td className="small">{i.reason}</td>
                </tr>
                {open === i.id && (
                  <tr className="detail-row"><td colSpan={5}>
                    <div className="row-between"><b>Evidence</b><AiNote ai={i.ai} /></div>
                    {i.evidence.length > 0 && <ul className="small">{i.evidence.map((e, n) => <li key={n} className="mono">{e.file}:{e.line} {e.quote && `“${e.quote}”`}</li>)}</ul>}
                    {i.rule_verdict !== i.verdict && <p className="small muted">Rule-only verdict would be: {i.rule_verdict} ({i.rule_reason})</p>}
                    {(i.static?.hits ?? []).map((h, n) => <div key={n} className="small"><span className="chip">{h.rule}</span> <span className="mono">{h.file}:{h.line}</span> {h.message}{h.code && <span className="mono muted"> — {h.code}</span>}</div>)}
                    {Object.entries(i.code).map(([file, lines]) => (
                      <CodeView key={file} file={file} lines={file === 'package.json' && i.hook_lines?.length
                        ? lines.slice(Math.max(0, i.hook_lines[0] - 4), i.hook_lines[i.hook_lines.length - 1] + 3) : lines}
                        start={file === 'package.json' && i.hook_lines?.length ? Math.max(1, i.hook_lines[0] - 3) : 1}
                        highlight={[...(file === 'package.json' ? i.hook_lines ?? [] : []), ...i.evidence.filter((e) => e.file === file).map((e) => e.line),
                          ...(i.static?.hits ?? []).filter((h) => h.file === file).map((h) => h.line)]} />
                    ))}
                  </td></tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        {data.items.length === 0 && <p className="muted">No package needed investigation.</p>}
        {!!data.config_items?.length && <ConfigTable items={data.config_items} />}
        {ruleFacts.length > 0 && (
          <div className="small">
            <h2 className="section-title">Not investigated (repo-wide rule facts)</h2>
            <p className="muted">These describe the whole project, not a package or a file line, so there is nothing for the agent to inspect.</p>
            <ul>{ruleFacts.map((f) => (
              <li key={f.id}><span className="chip">{f.rule}</span> {f.title}. {f.rule === 'no-lockfile'
                ? 'Fix: commit a package-lock.json so every install gets the versions that were scanned.' : f.rationale}</li>
            ))}</ul>
          </div>
        )}
        {!!data.not_investigated?.length && <p className="small muted">Not investigated (limit of 25 per scan; lower priority):{' '}
          <span className="mono">{data.not_investigated.join(', ')}</span></p>}
      </section>
    </div>
  )
}

function ConfigTable({ items }: { items: ConfigItem[] }) {
  const [open, setOpen] = useState<string | null>(null)
  return (
    <>
      <h2 className="section-title">Repo configuration findings</h2>
      <p className="small muted">Workflow and Dockerfile findings from Suspicious changes. Nothing is downloaded: the
        agent reads the lines around each finding, runs built-in checks, then asks the AI.</p>
      <table className="table">
        <thead><tr><th>Verdict</th><th>Where</th><th>Finding</th><th>Checks</th><th>Reason</th></tr></thead>
        <tbody>
          {items.map((i) => (
            <Fragment key={i.id}>
              <tr className="clickable" onClick={() => setOpen(open === i.id ? null : i.id)}>
                <td><span className={`sev ${VERDICT_CLASS[i.verdict]}`}>{i.verdict}
                  {i.confidence != null && <b>{Math.round(i.confidence * 100)}%</b>}</span>
                  <div className="small muted">{i.basis}</div></td>
                <td className="mono small">{i.file}:{i.line}</td>
                <td className="small"><span className="chip">{i.rule}</span><div>{i.title}</div></td>
                <td className="small">{i.static.hits.map((h) => <div key={h.rule}>{h.message}</div>)}</td>
                <td className="small">{i.reason}</td>
              </tr>
              {open === i.id && (
                <tr className="detail-row"><td colSpan={5}>
                  <div className="row-between"><b>Evidence</b><AiNote ai={i.ai} /></div>
                  {i.verdict !== i.rule_verdict && <p className="small muted">Rule-only verdict would be: {i.rule_verdict} ({i.rule_reason})</p>}
                  <CodeView file={i.snippet.file} lines={i.snippet.lines} start={i.snippet.start}
                            highlight={[i.line, ...i.evidence.map((e) => e.line)]} />
                </td></tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </>
  )
}
