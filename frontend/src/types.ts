export type AgentStatus = 'pending' | 'running' | 'done' | 'partial' | 'failed' | 'skipped' | 'planned'

export interface Agent {
  name: string
  status: AgentStatus
  summary?: string
  duration?: number
  error?: string
}

export interface Component {
  id: string
  name: string
  version: string
  ecosystem: string
  purl: string
  direct: boolean
  scope: 'runtime' | 'dev' | 'optional'
  license: string | null
  origin: string
  resolved: string | null
  integrity: string | null
  install_script: boolean
  projects: string[]
  install_paths: number
}

export interface Project {
  id: string
  path: string
  ecosystem: string
  manifest: string
  name?: string
  version?: string
  lockfile?: string | null
  lock_source?: 'committed' | 'generated' | 'none'
  status: 'parsed' | 'partial' | 'failed'
  component_count: number
  declared_direct?: number
  notes: string[]
  evidence: { command?: string; npm_version?: string; generated_at?: string; sha256?: string; artifact?: string }
}

export interface GraphNode {
  id: string
  label: string
  type: 'repo' | 'project' | 'component'
  depth: number | null
  direct?: boolean
  scope?: string
  ecosystem?: string
  dependents?: number
  dependencies?: number
}

export interface GraphEdge { source: string; target: string; kind: string }

export interface Observation { file: string; line: number | null; text: string; level: 'info' | 'notice' | 'warning'; message: string }

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unrated' | 'none'

export interface VulnFinding {
  id: string; type: 'vulnerability'; advisory_id: string; aliases: string[]; cves: string[]
  title: string; severity: Severity; severity_source: string; cvss_score: number | null; cvss_vector: string | null
  advisory_label: string | null; cwe: string[]; fixed_versions: string[]; fix: string | null
  published?: string; url: string; component: string; name: string; version: string; ecosystem: string
  direct: boolean | null; scope: string | null; path: string[] | null; project: string; also_in?: string[]
  trivy_confirmed?: boolean
}

export interface SuspiciousFinding {
  id: string; type: 'suspicious'; rule: string; category: string; title: string
  severity: 'high' | 'medium' | 'low'; status: 'fact' | 'indicator'; rationale: string
  evidence: { file?: string; line?: number | null; text?: string; source?: string; field?: string; resolved?: string | null; lookalike_of?: string; notes?: string[]; command?: string }
  component: string | null; name: string | null; version: string | null; direct: boolean | null
  scope: string | null; path: string[] | null; project: string | null
}

export interface Bundle {
  finding_id: string; type: 'vulnerability' | 'suspicious'; title: string; severity: string
  advisory_id?: string | null; aliases: string[]; rule?: string | null; category: string
  component: { purl: string; name: string; version: string; direct: boolean; scope: string } | null
  project: string | null; dependency_path: string[]; fix: string | null
  evidence_refs: { kind: string; ref: string; line?: number | null; detail?: string }[]
  verified_facts: string[]; inference: string[]; unknowns: string[]
  initial_risk: { level: 'critical' | 'high' | 'medium' | 'low' | 'review'; rationale: string }
}

export interface AiResult {
  ok: boolean; reason?: string; answer?: Record<string, any>; model?: string; cached?: boolean
  attempts?: number; problems?: string[]; downgraded?: boolean
}
export interface Citation { file: string; line: number; quote?: string; code?: string }
export interface Snippet { file: string; line: number; start: number; lines: string[] }

export interface Hit { rule: string; file: string; line: number; code: string; message: string }

export interface ConfigItem {
  id: string; component: string; package: string; file: string; line: number; rule: string; category: string
  title: string; text: string; static: { status: string; hits: Hit[] }; rule_verdict: string; rule_reason: string
  snippet: { file: string; start: number; lines: string[] }; ai: AiResult
  verdict: 'malicious' | 'risky' | 'harmless'; confidence: number | null; basis: string; reason: string; evidence: Citation[]
}

export interface Investigation {
  id: string; component: string; package: string; version: string; flagged_by: string[]
  scope: string; direct: boolean; path: string[] | null; mal_advisories: string[]
  tarball: { file?: string; size?: number; integrity?: string; integrity_match?: boolean; command?: string; error?: string }
  install_scripts: { hook: string; command: string }[]
  guarddog: { status: string; hits: Hit[]; reason?: string }
  static?: { status: string; hits: Hit[] }
  rule_verdict: string; rule_reason: string; code: Record<string, string[]>; hook_lines?: number[]
  ai: AiResult; verdict: 'malicious' | 'risky' | 'harmless' | 'unknown'; confidence: number | null
  basis: string; reason: string; evidence: Citation[]
}

export interface Risk {
  id: string; rank: number; component: string; package: string; version: string; scope: string; direct: boolean
  path: string[]; controlled_by: string | null
  advisories: { id: string; cves: string[]; cvss: number | null; severity: string; title: string; fix: string | null; url: string; cwe: string[] }[]
  cvss: number; cvss_source: string; kev: string[]; epss: number | null
  factors: { U: number; D: number; P: number; E: number; R: number }
  base_score: number; final_score: number; formula: string; band: 'critical' | 'high' | 'medium' | 'low'
  protected: boolean; labels: string[]; confidence: string
  reachability: 'reachable' | 'unknown' | 'not_reachable'; reachability_basis: string; reason?: string
  evidence: Citation[]; usage_snippets?: Snippet[]; ai: AiResult
  investigation: { verdict: string; basis: string } | null
}

export interface FixCard {
  id: string; risk_id: string; rank: number; package: string; version: string; band: string
  action: 'upgrade' | 'upgrade-parent' | 'upgrade-all' | 'relock' | 'override' | 'replace' | 'remove' | 'pin' | 'config'; title: string; also_fixes?: string[]
  change: { package: string; from: string; to: string; spec_from: string | null; spec_to: string; field: string | null; manifest: string; jump: string } | null
  patch: string | null; rollback: { version: string; how: string } | null
  resolution?: { package: string; version: string; range?: string }[]; target_after?: string
  advisories_removed: string[]; cves_removed: string[]; remaining: string[]
  score_before: number; score_after: number; band_after?: string
  evidence: { registry?: string[]; changelog?: string }; usage_snippets?: Snippet[]
  ai: AiResult; compatibility: { jump: string | null; breaking_risk: string | null }
  plain?: { text: string; source: 'AI' | 'rule' }
  changes?: NonNullable<FixCard['change']>[]; routes?: string[]; vetting?: string
  packages?: { package: string; version: string; band: string; score_before: number; score_after: number }[]
}

export interface Validation {
  card_id: string; status: string; reason?: string; branch?: string; workspace?: string; card_title?: string
  steps?: { name: string; status: string; detail: string; at: string; mode?: string; log?: string; diff?: string }[]
  comparison?: { target_fixed: boolean; summary: string; new_high_risk: string[]
                 sbom_diff: { added: string[]; removed: string[]; changed: string[] }
                 new_advisories: { package: string; id: string; severity: string }[]
                 new_suspicious: { title: string; severity: string; rule: string }[]
                 advisories_before: number; advisories_after: number }
  build?: { status: string; mode?: string; detail: string; log?: string
            smoke?: { status: string; detail: string; http_status?: number | null; url?: string; log_excerpt?: string } }
  ai?: AiResult
  applied?: string[]; not_applied?: { fix: string; why: string }[]
}

export interface Decision { card_id: string; decision: 'approved' | 'rejected'; decided_by: string; note: string; decided_at: string }
export interface LlmStatus { enabled: boolean; model: string; base_url: string; answered?: number; candidates?: number; tokens?: number }

export interface Results {
  checkout?: {
    owner: string; repo: string; url: string; commit_sha: string; branch: string
    commit_date: string; commit_author: string; commit_subject: string; tracked_files: number; clone: string
  }
  discovery?: {
    projects: Project[]
    unsupported: { path: string; ecosystem: string }[]
    warnings: string[]
    ecosystems: string[]
    components: Component[]
    stats: { components: number; direct: number; transitive: number; edges: number; install_scripts: number }
  }
  sbom?: {
    format: string; spec_version: string; artifact: string; sha256: string; size_bytes: number
    components: number; dependency_entries: number; serial_number: string
    crosschecks: { project: string; tool: string; ours: number; status: string; tool_count?: number; artifact?: string; error?: string }[]
  }
  graph?: {
    nodes: GraphNode[]; edges: GraphEdge[]; paths: Record<string, string[]>
    stats: { nodes: number; edges: number; max_depth: number; depth_histogram: Record<string, number>; unreachable: number }
    most_depended_on: { id: string; dependents: number }[]
  }
  inspection?: {
    dockerfiles: { file: string; images: { image: string; stage: string | null; line: number; pinning: string; level: string }[]; observations: Observation[] }[]
    workflows: { file: string; actions: { uses: string; line: number; kind: string; pinned: boolean; first_party: boolean }[]; observations: Observation[] }[]
    observations: Observation[]
    not_inspected: string[]
    stats: { dockerfiles: number; workflows: number; base_images: number; actions: number; unpinned_actions: number; warnings: number }
  }
  vulnerability?: {
    scans: { project: string; manifest: string; status: string; command?: string; tool_version?: string; mode?: string
             scanned_at?: string; target?: string; target_sha256?: string; artifact?: string; findings?: number
             packages_affected?: number; error?: string; reason?: string
             trivy?: { version: string; status: string; artifact?: string; trivy_entries?: number; matched_osv?: number; only_trivy?: string[]; error?: string } }[]
    findings: VulnFinding[]
    counts: Record<'critical' | 'high' | 'medium' | 'low' | 'unrated', number>
    packages_affected: number
  }
  change_detection?: {
    findings: SuspiciousFinding[]
    by_rule: Record<string, number>
    not_applicable: { rule: string; reason: string }[]
    counts: Record<'high' | 'medium' | 'low', number>
  }
  evidence?: {
    report: {
      repository: string; repo_url: string; commit_sha: string; generated_at: string
      inventory: { components: number; direct: number; transitive: number; edges: number }
      risk_counts: Record<string, number>; by_type: Record<string, number>
      coverage: { agents: { name: string; status: string; summary?: string }[]; gaps: string[] }
      checklist: { item: string; done: boolean }[]
    }
    bundles: Bundle[]
    artifacts: { json: string; markdown: string }
  }
  investigate?: { items: Investigation[]; config_items?: ConfigItem[]; config_counts?: Record<string, number>; not_investigated?: string[]; counts: Record<string, number>; guarddog: { status: string; tool?: string; seconds?: number; reason?: string }; llm: LlmStatus }
  prioritize?: {
    risks: Risk[]; counts: Record<string, number>; reachability: Record<string, number>
    feeds: { kev: { status: string; source: string; catalog_version?: string; entries?: number; fetched?: string; reason?: string }
             epss: { status: string; source?: string; cves_scored?: number; reason?: string } }
    llm: LlmStatus
  }
  remediate?: { cards: FixCard[]; errors: { package: string; error: string }[]; llm: LlmStatus }
  approval?: { requests: { card_id: string; title: string; action: string; band: string }[]; policy: string }
}

export interface Scan {
  id: string
  repo_url: string
  status: 'queued' | 'running' | 'cancelling' | 'cancelled' | 'completed' | 'failed'
  created_at: number
  commit_sha: string | null
  error: string | null
  agents: Record<string, Agent>
  results: Results
  decisions?: Record<string, Decision>
  validations?: Record<string, Validation>
  llm?: LlmStatus
}

export type ScanSummary = Pick<Scan, 'id' | 'repo_url' | 'status' | 'commit_sha' | 'created_at'>

export const artifactUrl = (scanId: string, name: string) => `/api/scans/${scanId}/artifacts/${name}`
