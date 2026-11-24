import { useEffect, useState } from 'react'
import type { Scan, ScanSummary } from './types'
import { AgentPipeline, Overview } from './Overview'
import GraphView, { type Theme } from './GraphView'
import SbomTable from './SbomTable'
import Inspection from './Inspection'
import Vulnerabilities from './Vulnerabilities'
import Suspicious from './Suspicious'
import Report from './Report'
import InvestigationTab from './InvestigationTab'
import RisksTab from './RisksTab'
import FixesTab from './FixesTab'
import ValidationTab from './ValidationTab'

const TABS = [
  ['overview', 'Overview'],
  ['graph', 'Dependency graph'],
  ['sbom', 'SBOM'],
  ['inspection', 'Container & CI/CD'],
  ['vulnerability', 'Vulnerabilities'],
  ['change_detection', 'Suspicious changes'],
  ['evidence', 'Evidence report'],
  ['investigate', 'Investigation'],
  ['prioritize', 'Prioritized risks'],
  ['remediate', 'Fixes & approval'],
  ['validation', 'Fixed app & report'],
] as const
type Tab = (typeof TABS)[number][0]


const shortRepo = (url: string) => url.replace('https://github.com/', '')
const when = (t: number) => new Date(t * 1000).toLocaleString()

function useHashRoute(): [string | null, (id: string | null) => void] {
  const read = () => location.hash.match(/^#\/scan\/(\w+)/)?.[1] ?? null
  const [id, setId] = useState(read)
  useEffect(() => {
    const on = () => setId(read())
    addEventListener('hashchange', on)
    return () => removeEventListener('hashchange', on)
  }, [])
  return [id, (next) => { location.hash = next ? `/scan/${next}` : '' }]
}

function useTheme() {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem('theme')
      if (saved === 'light' || saved === 'dark') return saved
    } catch { /* storage blocked: fall back to OS preference */ }
    return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('theme', theme) } catch { /* not persisted */ }
  }, [theme])
  return [theme, setTheme] as const
}

export default function App() {
  const [scanId, go] = useHashRoute()
  const [theme, setTheme] = useTheme()
  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href="#" onClick={() => go(null)}>
          <span className="logo">◆</span> Supply Chain Guardian
        </a>
        <span className="topbar-sub">Agentic software supply-chain analysis</span>
        <button className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
          {theme === 'dark' ? '☀ Light' : '☾ Dark'}
        </button>
      </header>
      <main>{scanId ? <ScanPage id={scanId} theme={theme} /> : <Home onScan={go} />}</main>
    </div>
  )
}

function Home({ onScan }: { onScan: (id: string) => void }) {
  const [url, setUrl] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [scans, setScans] = useState<ScanSummary[]>([])
  useEffect(() => { fetch('/api/scans').then((r) => r.json()).then(setScans).catch(() => {}) }, [])

  async function stop(s: ScanSummary) {
    if (!confirm(`Stop the running scan of ${shortRepo(s.repo_url)}? The current agent finishes its step, then the scan stops.`)) return
    const r = await fetch(`/api/scans/${s.id}/cancel`, { method: 'POST' }).catch(() => null)
    if (!r?.ok) return setError(r ? (await r.json()).detail ?? 'Stop failed' : 'Backend not reachable on port 8000')
    const { status } = await r.json()
    setScans((all) => all.map((x) => (x.id === s.id ? { ...x, status } : x)))
  }

  async function remove(s: ScanSummary) {
    const ok = confirm(`Delete the scan of ${shortRepo(s.repo_url)} from ${when(s.created_at)}?

`
      + 'This permanently removes its results, evidence files and the cloned repository from this computer.')
    if (!ok) return
    const r = await fetch(`/api/scans/${s.id}`, { method: 'DELETE' }).catch(() => null)
    if (r?.ok) return setScans((all) => all.filter((x) => x.id !== s.id))
    setError(r ? (await r.json()).detail ?? 'Delete failed' : 'Backend not reachable on port 8000')
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    const r = await fetch('/api/scans', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ repo_url: url }),
    }).catch(() => null)
    setBusy(false)
    if (!r) return setError('Backend not reachable on port 8000')
    const body = await r.json()
    if (!r.ok) return setError(body.detail ?? 'Scan request failed')
    onScan(body.id)
  }

  return (
    <div className="home">
      <section className="hero">
        <h1>Scan a repository's software supply chain</h1>
        <p>
          Paste a public GitHub repository. The Guardian clones it at a pinned commit, discovers every direct and
          transitive dependency, generates a CycloneDX SBOM, maps the dependency graph and inspects containers and
          CI/CD. No repository code is executed.
        </p>
        <form className="scan-form" onSubmit={submit}>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/owner/repo"
                 aria-label="GitHub repository URL" spellCheck={false} />
          <button disabled={busy}>{busy ? 'Starting…' : 'Start scan'}</button>
        </form>
        {error && <div className="form-error">{error}</div>}
      </section>
      {scans.length > 0 && (
        <section className="card">
          <h2>Recent scans</h2>
          <table className="table">
            <thead><tr><th>Repository</th><th>Commit</th><th>Status</th><th>Started</th><th aria-label="Delete" /></tr></thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="clickable" onClick={() => onScan(s.id)}>
                  <td>{shortRepo(s.repo_url)}</td>
                  <td className="mono">{s.commit_sha?.slice(0, 12) ?? '—'}</td>
                  <td><span className={`badge ${s.status}`}>{s.status}</span></td>
                  <td>{when(s.created_at)}</td>
                  <td className="row-action">
                    {(s.status === 'queued' || s.status === 'running' || s.status === 'cancelling') && (
                      <button className="trash stop" onClick={(e) => { e.stopPropagation(); stop(s) }}
                              disabled={s.status === 'cancelling'} title="Stop this scan"
                              aria-label={`Stop scan of ${shortRepo(s.repo_url)}`}>
                        <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2" /></svg>
                      </button>
                    )}
                    <button className="trash" onClick={(e) => { e.stopPropagation(); remove(s) }}
                            title="Delete scan and its cloned repo (stop it first if it is running)"
                            aria-label={`Delete scan of ${shortRepo(s.repo_url)}`}>
                      <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor"
                           strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  )
}

function ScanPage({ id, theme }: { id: string; theme: Theme }) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [missing, setMissing] = useState(false)
  const [tab, setTab] = useState<Tab>('overview')
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let timer = 0
    const load = async () => {
      const r = await fetch(`/api/scans/${id}`).catch(() => null)
      if (r?.status === 404) return setMissing(true)
      if (r?.ok) {
        const s: Scan = await r.json()
        setScan(s)
        const validating = Object.values(s.validations ?? {}).some((v) => ['queued', 'running', 'applying', 'checking'].includes(v.status))
        if ((s.status === 'completed' || s.status === 'failed' || s.status === 'cancelled') && !validating) return
      }
      timer = window.setTimeout(load, 2000)
    }
    load()
    return () => clearTimeout(timer)
  }, [id, tick])

  if (missing) return <div className="card">Scan not found.</div>
  if (!scan) return <div className="card">Loading…</div>
  const co = scan.results.checkout
  const labels = new Map(scan.results.graph?.nodes.map((n) => [n.id, n.label]) ?? [])
  const label = (id: string) => labels.get(id) ?? id.replace(/^project:/, '')

  return (
    <div className="scan">
      <section className="scan-head card">
        <div>
          <div className="eyebrow">Repository</div>
          <h1><a href={scan.repo_url} target="_blank" rel="noreferrer">{shortRepo(scan.repo_url)}</a></h1>
          {co && (
            <div className="meta">
              <span>branch <b>{co.branch}</b></span>
              <span>commit <b className="mono">{co.commit_sha.slice(0, 12)}</b></span>
              <span>{new Date(co.commit_date).toLocaleDateString()} · {co.commit_author}</span>
              <span className="subject">“{co.commit_subject}”</span>
            </div>
          )}
        </div>
        <span className={`badge big ${scan.status}`}>{scan.status}</span>
      </section>
      {scan.error && <div className="alert">Scan failed: {scan.error}. Results below are incomplete; nothing here means “clean”.</div>}

      <AgentPipeline agents={scan.agents} onPick={(k) => TABS.some(([t]) => t === k) && setTab(k as Tab)} />

      <nav className="tabs">
        {TABS.map(([key, label]) => (
          <button key={key} className={`${tab === key ? 'active' : ''}`} onClick={() => setTab(key)}>
            {label}
            {scan.agents[key]?.status === 'planned' && <span className="soon">planned</span>}
          </button>
        ))}
      </nav>

      <div className="tab-body">
        {tab === 'overview' && <Overview scan={scan} />}
        {tab === 'graph' && (scan.results.graph && scan.results.discovery
          ? <GraphView graph={scan.results.graph} components={scan.results.discovery.components} theme={theme} />
          : <Waiting agent={scan.agents.graph} />)}
        {tab === 'sbom' && (scan.results.sbom && scan.results.discovery
          ? <SbomTable scanId={scan.id} sbom={scan.results.sbom} discovery={scan.results.discovery} paths={scan.results.graph?.paths} />
          : <Waiting agent={scan.agents.sbom} />)}
        {tab === 'inspection' && (scan.results.inspection
          ? <Inspection data={scan.results.inspection} repoUrl={scan.repo_url} sha={scan.commit_sha} />
          : <Waiting agent={scan.agents.inspection} />)}
        {tab === 'vulnerability' && (scan.results.vulnerability
          ? <Vulnerabilities scanId={scan.id} data={scan.results.vulnerability} label={label} />
          : <Waiting agent={scan.agents.vulnerability} />)}
        {tab === 'change_detection' && (scan.results.change_detection
          ? <Suspicious data={scan.results.change_detection} label={label} repoUrl={scan.repo_url} sha={scan.commit_sha} />
          : <Waiting agent={scan.agents.change_detection} />)}
        {tab === 'investigate' && (scan.results.investigate
          ? <InvestigationTab data={scan.results.investigate} suspicious={scan.results.change_detection?.findings ?? []} />
          : <Waiting agent={scan.agents.investigate ?? { name: 'Investigate', status: 'planned' }} />)}
        {tab === 'prioritize' && (scan.results.prioritize
          ? <RisksTab data={scan.results.prioritize} />
          : <Waiting agent={scan.agents.prioritize ?? { name: 'Prioritize', status: 'planned' }} />)}
        {tab === 'remediate' && (scan.results.remediate
          ? <FixesTab scanId={scan.id} data={scan.results.remediate} decisions={scan.decisions ?? {}} onDecided={() => setTick((t) => t + 1)}
                       risks={scan.results.prioritize?.risks} validations={scan.validations ?? {}} />
          : <Waiting agent={scan.agents.remediate ?? { name: 'Recommend Fix', status: 'planned' }} />)}
        {tab === 'validation' && (scan.results.remediate
          ? <ValidationTab scanId={scan.id} cards={scan.results.remediate.cards} validations={scan.validations ?? {}}
                           onRerun={() => setTick((t) => t + 1)} />
          : <Waiting agent={scan.agents.remediate ?? { name: 'Recommend Fix', status: 'planned' }} />)}
        {tab === 'evidence' && (scan.results.evidence
          ? <Report scanId={scan.id} data={scan.results.evidence} repoUrl={scan.repo_url} sha={scan.commit_sha} />
          : <Waiting agent={scan.agents.evidence} />)}
      </div>
    </div>
  )
}

function Waiting({ agent }: { agent: Scan['agents'][string] }) {
  const msg = agent.status === 'failed' ? `Failed: ${agent.error}`
    : agent.status === 'skipped' ? 'Skipped because an earlier agent failed.'
    : agent.status === 'planned' ? `${agent.name} did not exist when this scan ran. Start a new scan to get its results; until then this scan makes no claim here.`
    : `${agent.name} is ${agent.status}…`
  return <div className="card muted">{msg}</div>
}
