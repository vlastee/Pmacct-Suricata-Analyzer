export interface Totals {
  bytes: number; packets: number; flows: number; local_hosts: number; external_ips: number
  bytes_in: number; bytes_out: number; bytes_local: number
}
export interface Bucket { time: string; bytes: number; bytes_in: number; bytes_out: number; packets: number; flows: number }
export interface ProtoStat { proto: number; name: string; bytes: number; packets: number; flows: number }
export interface PortStat { port: number; proto: number; name: string; service: string; bytes: number; packets: number; flows: number }
export interface VTResult {
  malicious: number | null; suspicious: number | null; harmless: number | null; undetected: number | null
  reputation: number | null; tags: string[] | null; network: string | null; last_analysis: string | null
  status: string; error: string | null; attempts: number; lookup_at: string | null
}
export interface IPInfo {
  ip: string; hostname: string | null; country: string | null; country_code: string | null; region: string | null
  city: string | null; lat: number | null; lon: number | null; timezone: string | null; asn: string | null
  as_org: string | null; isp: string | null; org: string | null; is_hosting: boolean | null; is_proxy: boolean | null
  is_mobile: boolean | null; source: string | null; status: string; error: string | null; attempts: number
  first_seen: string; last_lookup: string | null; updated_at: string; vt?: VTResult | null
  names?: IPName[]; reputation?: Reputation[]; lists?: string[]
}
export interface IPName { name: string; source: string; hits: number; last_seen: string }
export interface Reputation { source: string; status: string; error: string | null; attempts: number; lookup_at: string; score: number | null; flagged: boolean; data: any }
export interface Nickname { ip: string; nickname: string; note: string | null; kind: string; updated_at: string }
export interface Alert {
  id: number; rule: string; severity: string; host: string | null; host_nickname: string | null
  peer: string | null; peer_nickname: string | null; port: number | null; title: string; details: any
  count: number; first_seen: string; last_seen: string; state: string; acked_at: string | null
  resolved_at: string | null; notified_at: string | null; host_excluded?: string; peer_excluded?: string
}
export interface TLSInfo {
  enabled: boolean; addr?: string; url?: string; ca_subject?: string; ca_fingerprint_sha256?: string; ca_spki_sha256?: string
  ca_not_after?: string; hosts?: string[]; leaf_not_after?: string; leaf_issued_at?: string
}
export interface Agent {
  id: number; name: string; hostname: string; os: string; arch: string; version: string; ips: string[]; capture: string
  enrolled_at: string; last_seen: string | null; last_ip: string | null; events_total: number; last_batch: number; dropped: number
  revoked_at: string | null; note: string
}
export interface EnrollToken { enroll_token: string; expires_at: string; server_url: string; tls_required: boolean; ca_fingerprint_sha256?: string; ca_spki_sha256?: string }
export interface ProcessStat { exe: string; name: string; user: string; sha256: string; conns: number; bytes: number; peers: number; ports: number; last_seen: string; top_peers: string[] }
export interface IPNote { id: number; ip: string; body: string; author: string; created_at: string }
export interface Exclusion { id: number; pattern: string; kind: 'ip' | 'cidr' | 'name'; note: string; created_at: string }
export interface AlertRetention { auto_resolve_days: number; delete_resolved_days: Record<string, number> }
export interface AlertSummary { open: number; acked: number; critical: number; warning: number; info: number; by_rule: Record<string, number>; last_24h: number }
export interface RuleParam { name: string; description: string; default: any }
export interface RuleInfo {
  name: string; title: string; description: string; enabled: boolean; severity: string; interval: string; window: string
  default_severity: string; default_interval: string; default_window: string
  params: RuleParam[]; values: Record<string, any>; exempt_hosts: string[]
  custom: boolean; kind?: 'sql' | 'builtin'; base?: string; sql?: string
  last_run: string | null; last_findings: number; last_error?: string; last_ms: number
}
// A user-defined rule: either your own SQL, or a built-in detector with your own settings.
export interface CustomRuleSpec {
  name: string; title: string; description: string; kind: 'sql' | 'builtin'; base?: string; sql?: string
  params?: Record<string, any>; severity: string; interval: string; window: string; enabled?: boolean; exempt_hosts?: string[]
}
export interface Finding { rule: string; severity: string; host?: string; peer?: string; port?: number; title: string; details: any; key?: string }
export interface IDSEvent {
  id: number; ts: string; src_ip: string | null; src_port: number | null; dst_ip: string | null; dst_port: number | null
  proto: string | null; sid: number | null; signature: string | null; category: string | null; severity: number | null
  action: string | null; app_proto: string | null; src_nickname: string | null; dst_nickname: string | null; raw?: any
}
export interface IDSSignatureStat { sid: number; signature: string; category: string | null; severity: number | null; count: number; sources: number; last_seen: string }
export interface IDSTypeStat { type: string; count: number; last: string; used?: string }
export interface IDSListener {
  listen: string; started?: string; received: number; alerts: number; names: number; dropped: number; malformed: number; ignored: number
  last_event?: string; last_error?: string; last_error_at?: string; types: IDSTypeStat[]
}
export interface Nickname { ip: string; nickname: string; note: string | null; updated_at: string }
export interface HostRisk { score: number; critical: number; warning: number; info: number }
export interface HostStat {
  ip: string; nickname: string | null; local: boolean; bytes_in: number; bytes_out: number; bytes: number; packets: number; flows: number
  peers: number; first_seen: string; last_seen: string; names: string[]; risk?: HostRisk | null; info?: IPInfo | null
}
export interface Flow {
  ip_src: string; ip_dst: string; src_nickname: string | null; dst_nickname: string | null; port_src: number; port_dst: number; proto: number; proto_name: string
  packets: number; bytes: number; stamp_inserted: string; stamp_updated: string | null
}
export interface GroupStat { key: string; label: string; ips: number; bytes_in: number; bytes_out: number; bytes: number; flows: number }
export interface Threat {
  ip: string; nickname: string | null; malicious: number; suspicious: number; tags: string[]; bytes: number; flows: number
  local_hosts: string[]; last_seen: string; info?: IPInfo | null
}
export interface Overview {
  window: { since: string; until: string; interval_seconds: number }
  totals: Totals; timeseries: Bucket[]; protocols: ProtoStat[]; ports: PortStat[]
  top_local: HostStat[]; top_external: HostStat[]; countries: GroupStat[]; threats: Threat[]; alerts: AlertSummary
}
export interface HostDetail {
  host: HostStat; kind: string; peers: HostStat[]; ports: PortStat[]; timeseries: Bucket[]
  alerts: Alert[]; ids_events: IDSEvent[]; hourly: { hour: string; bytes_in: number; bytes_out: number; flows: number; peers: number }[]
  window: { since: string; until: string; interval_seconds: number }
}
export interface LaneStats {
  enabled: boolean; provider: string; running: boolean; last_run: string; last_batch_size: number; runs: number
  lookups: number; failures: number; interval: string; refresh_after: string; rate_limit: string
  daily_quota?: number; quota_used?: number; monthly_quota?: number; quota_used_month?: number; quota_hit?: boolean
}
export interface EnrichmentStatus {
  enabled: boolean
  table: { total: number; ok: number; pending: number; failed: number; stale: number; vt_done: number; vt_failed: number; vt_never: number; vt_stale: number; vt_used_today: number; vt_used_month: number; vt_flagged: number }
  lanes?: Record<string, LaneStats>
}
export interface AuthUser { id: number; username: string; is_admin: boolean; must_change_password: boolean; disabled: boolean; created_at: string; last_login: string | null; last_login_ip: string | null }
export interface LoginActivity { ip: string | null; username: string | null; success: boolean; reason: string | null; ts: string; user_agent: string | null }
export interface AttemptStat { ip: string; failures: number; successes: number; last_seen: string; blocked: boolean; blocked_until: string | null }
export interface IPRule { net: string; action: string; source: string; note: string | null; created_at: string; expires_at: string | null }
export interface Meta { local_networks: string[]; data_from: string | null; data_to: string | null; enrichment: boolean; now: string }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init)
  const text = await res.text()
  let body: any = null
  try { body = text ? JSON.parse(text) : null } catch { body = null }
  if (!res.ok) throw new ApiError(res.status, body?.error ?? `${res.status} ${res.statusText}`)
  return body as T
}

function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

export type Range = { since: string; until?: string } & Record<string, string | undefined>

export const api = {
  meta: () => request<Meta>('/api/v1/meta'),
  overview: (r: Range) => request<Overview>(`/api/v1/overview${qs(r)}`),
  timeseries: (r: Range, ip?: string) => request<{ interval_seconds: number; points: Bucket[] }>(`/api/v1/timeseries${qs({ ...r, ip })}`),
  hosts: (r: Range, o: { scope?: string; sort?: string; order?: string; q?: string; country?: string; asn?: string; limit?: number; offset?: number }) =>
    request<{ items: HostStat[]; total: number; limit: number; offset: number }>(`/api/v1/hosts${qs({ ...r, ...o })}`),
  host: (ip: string, r: Range) => request<HostDetail>(`/api/v1/hosts/${encodeURIComponent(ip)}${qs(r)}`),
  flows: (r: Range, o: { ip?: string; port?: number; proto?: number; limit?: number; offset?: number }) =>
    request<{ items: Flow[] }>(`/api/v1/flows${qs({ ...r, ...o })}`),
  groups: (dim: string, r: Range, limit = 25) => request<{ items: GroupStat[] }>(`/api/v1/groups/${dim}${qs({ ...r, limit })}`),
  protocols: (r: Range) => request<{ items: ProtoStat[] }>(`/api/v1/protocols${qs(r)}`),
  ports: (r: Range) => request<{ items: PortStat[] }>(`/api/v1/ports${qs(r)}`),
  threats: (r: Range) => request<{ items: Threat[] }>(`/api/v1/threats${qs(r)}`),
  ipInfo: (ip: string) => request<IPInfo>(`/api/v1/ips/${encodeURIComponent(ip)}`),
  ipList: (q: string, limit = 100, offset = 0) => request<{ items: IPInfo[] }>(`/api/v1/ips${qs({ q, limit, offset })}`),
  refreshIP: (ip: string) => request<IPInfo>(`/api/v1/ips/${encodeURIComponent(ip)}/refresh`, { method: 'POST' }),
  enrichmentStatus: () => request<EnrichmentStatus>('/api/v1/enrichment/status'),
  enrichmentRun: () => request<{ queued: boolean }>('/api/v1/enrichment/run', { method: 'POST' }),
  nicknames: (q = '') => request<{ items: Nickname[] }>(`/api/v1/nicknames${qs({ q })}`),
  setNickname: (ip: string, nickname: string, note: string | null, kind?: string) =>
    request<Nickname>(`/api/v1/nicknames/${encodeURIComponent(ip)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nickname, note, kind }) }),
  deleteNickname: (ip: string) => request<void>(`/api/v1/nicknames/${encodeURIComponent(ip)}`, { method: 'DELETE' }),
  kinds: () => request<{ items: string[] }>('/api/v1/kinds'),
  alerts: (o: { state?: string; severity?: string; rule?: string; host?: string; limit?: number; offset?: number } = {}) =>
    request<{ items: Alert[]; total: number }>(`/api/v1/alerts${qs(o)}`),
  alertSummary: () => request<AlertSummary>('/api/v1/alerts/summary'),
  alertAction: (id: number, action: 'ack' | 'resolve' | 'reopen') => request<Alert>(`/api/v1/alerts/${id}/${action}`, { method: 'POST' }),
  resolveAlerts: (o: { rule?: string; host?: string }) => request<{ resolved: number }>(`/api/v1/alerts/resolve${qs(o)}`, { method: 'POST' }),
  deleteResolvedAlerts: (o: { rule?: string; host?: string; severity?: string }) => request<{ deleted: number }>(`/api/v1/alerts/resolved${qs(o)}`, { method: 'DELETE' }),
  deleteAlert: (id: number) => request<{ deleted: number }>(`/api/v1/alerts/${id}`, { method: 'DELETE' }),
  alertSettings: () => request<AlertRetention>('/api/v1/alerts/settings'),
  setAlertSettings: (r: AlertRetention) =>
    request<{ settings: AlertRetention; deleted: Record<string, number> }>('/api/v1/alerts/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(r) }),
  rules: () => request<{ enabled: boolean; interval?: string; items: RuleInfo[] }>('/api/v1/rules'),
  updateRule: (name: string, body: { enabled?: boolean; severity?: string; params?: Record<string, any>; exempt_hosts?: string[]; interval?: string; window?: string }) =>
    request<RuleInfo>(`/api/v1/rules/${encodeURIComponent(name)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  runRule: (name: string) => request<{ raised: Alert[] }>(`/api/v1/rules/${encodeURIComponent(name)}/run`, { method: 'POST' }),
  previewRule: (name: string) => request<{ findings: Finding[] }>(`/api/v1/rules/${encodeURIComponent(name)}/run?dry=1`, { method: 'POST' }),
  createCustomRule: (spec: CustomRuleSpec) =>
    request<RuleInfo>('/api/v1/rules/custom', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(spec) }),
  updateCustomRule: (name: string, spec: CustomRuleSpec) =>
    request<RuleInfo>(`/api/v1/rules/custom/${encodeURIComponent(name)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(spec) }),
  deleteCustomRule: (name: string) => request<{ deleted: string }>(`/api/v1/rules/custom/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  previewCustomRule: (spec: CustomRuleSpec) =>
    request<{ findings: Finding[] }>('/api/v1/rules/custom/preview', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(spec) }),
  idsEvents: (r: Range, o: { ip?: string; sid?: number; limit?: number } = {}) => request<{ items: IDSEvent[] }>(`/api/v1/ids/events${qs({ ...r, ...o })}`),
  idsSummary: (r: Range) => request<{ items: IDSSignatureStat[]; total: number; enabled: boolean; listener?: IDSListener; last_stored_event?: string }>(`/api/v1/ids/summary${qs(r)}`),
  idsEvent: (id: number) => request<IDSEvent>(`/api/v1/ids/events/${id}`),
  ipNames: (ip: string) => request<{ items: IPName[] }>(`/api/v1/ips/${encodeURIComponent(ip)}/names`),
  systemStatus: () => request<any>('/api/v1/system/status'),
  tlsInfo: () => request<TLSInfo>('/api/v1/tls/info'),
  notifyTest: () => request<{ results: Record<string, string> }>('/api/v1/notify/test', { method: 'POST' }),
  agents: () => request<{ items: Agent[]; tls_required: boolean }>('/api/v1/agents'),
  createEnrollToken: (name: string) =>
    request<EnrollToken>('/api/v1/agents/enroll-tokens', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) }),
  updateAgent: (id: number, name: string, note: string) =>
    request<Agent>(`/api/v1/agents/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, note }) }),
  revokeAgent: (id: number) => request<{ ok: boolean }>(`/api/v1/agents/${id}/revoke`, { method: 'POST' }),
  deleteAgent: (id: number) => request<{ deleted: number }>(`/api/v1/agents/${id}`, { method: 'DELETE' }),
  hostProcesses: (ip: string, r: Range) => request<{ items: ProcessStat[]; via: Record<string, string[]>; agents: number }>(`/api/v1/hosts/${encodeURIComponent(ip)}/processes${qs(r)}`),
  ipNotes: (ip: string) => request<{ items: IPNote[] }>(`/api/v1/ips/${encodeURIComponent(ip)}/notes`),
  addIPNote: (ip: string, body: string) =>
    request<IPNote>(`/api/v1/ips/${encodeURIComponent(ip)}/notes`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ body }) }),
  deleteIPNote: (ip: string, id: number) => request<{ deleted: number }>(`/api/v1/ips/${encodeURIComponent(ip)}/notes/${id}`, { method: 'DELETE' }),
  exclusions: () => request<{ items: Exclusion[] }>('/api/v1/exclusions'),
  addExclusion: (pattern: string, note = '') =>
    request<{ item: Exclusion; resolved: number }>('/api/v1/exclusions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pattern, note }) }),
  deleteExclusion: (id: number) => request<{ deleted: number }>(`/api/v1/exclusions/${id}`, { method: 'DELETE' }),
  exclusionMatch: (ip: string) => request<{ ip: string; excluded: boolean; pattern: string }>(`/api/v1/exclusions/match?ip=${encodeURIComponent(ip)}`),
  notifySettings: (min_severity: string) =>
    request<any>('/api/v1/notify/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ min_severity }) }),
  me: () => request<{ auth: boolean; user?: AuthUser; must_change_password?: boolean }>('/api/v1/auth/me'),
  login: (username: string, password: string) =>
    request<{ user: AuthUser; must_change_password: boolean }>('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) }),
  logout: () => request<{ ok: boolean }>('/api/v1/auth/logout', { method: 'POST' }),
  changePassword: (current: string, next: string) =>
    request<{ ok: boolean }>('/api/v1/auth/change-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ current, new: next }) }),
  users: () => request<{ items: AuthUser[] }>('/api/v1/auth/users'),
  createUser: (username: string, password: string, is_admin: boolean) =>
    request<AuthUser>('/api/v1/auth/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password, is_admin }) }),
  userAction: (id: number, action: 'disable' | 'enable' | 'reset', password?: string) =>
    request<AuthUser>(`/api/v1/auth/users/${id}/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) }),
  deleteUser: (id: number) => request<void>(`/api/v1/auth/users/${id}`, { method: 'DELETE' }),
  securityActivity: (o: { ip?: string; user?: string; failures?: boolean } = {}) =>
    request<{ items: LoginActivity[] }>(`/api/v1/security/activity${qs({ ip: o.ip, user: o.user, failures: o.failures ? '1' : undefined })}`),
  securityAttackers: () => request<{ items: AttemptStat[] }>('/api/v1/security/attackers'),
  ipRules: () => request<{ items: IPRule[]; allowlist_only: boolean }>('/api/v1/security/ip-access'),
  addIPRule: (net: string, action: 'allow' | 'deny', note: string) =>
    request<IPRule>('/api/v1/security/ip-access', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ net, action, note }) }),
  deleteIPRule: (net: string) => request<void>(`/api/v1/security/ip-access${qs({ net })}`, { method: 'DELETE' }),
}
