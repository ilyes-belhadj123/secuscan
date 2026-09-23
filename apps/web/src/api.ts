export type Severity = "critical" | "high" | "medium" | "low";
export type FindingKind = "sast" | "ai" | "secret" | "dependency";
export type FindingStatus = "open" | "dismissed" | "false_positive";

export interface Explanation {
  definition: string;
  attack_scenario: string;
  business_impact: string;
  difficulty: string;
  references: string[];
}

export interface FixSuggestion {
  original_code: string;
  patched_code: string;
  diff: string;
  explanation: string;
  best_practices: string[];
  syntax_valid: boolean | null;
}

export interface AIReview {
  verdict: "true_positive" | "false_positive" | "uncertain";
  confidence: number;
  reason: string;
  explanation: Explanation | null;
  fix: FixSuggestion | null;
  model: string;
  cached: boolean;
  filtered: boolean;
  generated_by: "ai" | "osv";
}

export interface Advisory {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  fixed_version: string | null;
  url: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  kind: FindingKind;
  rule_id: string;
  title: string;
  message: string;
  fix_hint: string | null;
  language: string;
  file: string;
  start_line: number;
  end_line: number;
  snippet: string;
  snippet_start_line: number;
  cwe: string | null;
  owasp: string | null;
  raw_severity: Severity;
  severity: Severity;
  fingerprint: string;
  status: FindingStatus;
  dismiss_reason: string | null;
  dismiss_justification: string | null;
  ai: AIReview | null;
  ai_error: string | null;
  dependency: {
    ecosystem: string;
    package: string;
    version: string;
    manifest: string;
    advisories: Advisory[];
    fixed_version: string | null;
  } | null;
  secret: { secret_type: string; masked: string; fingerprint: string } | null;
}

export interface ScanSummary {
  total: number;
  by_severity: Record<Severity, number>;
  by_kind: Record<FindingKind, number>;
  by_owasp: Record<string, number>;
  false_positives: number;
  dismissed: number;
  files_scanned: number;
  lines_scanned: number;
  languages: Record<string, number>;
  ai_calls: number;
  ai_cache_hits: number;
  ai_tokens: number;
  ai_errors: number;
  ai_cost_usd: number;
  ai_budget_calls: number;
  ai_budget_refused: number;
  plan: string;
  warnings: string[];
  duration_seconds: number;
}

export interface Scan {
  id: string;
  project_name: string;
  source: "upload" | "snippet" | "demo" | "git";
  source_url: string | null;
  status: "queued" | "running" | "completed" | "failed";
  stage: string;
  progress: number;
  error: string | null;
  created_at: string;
  completed_at: string | null;
  score: number | null;
  summary: ScanSummary;
  ai_enabled: boolean;
  previous_scan_id: string | null;
  new_findings: number | null;
  fixed_findings: number | null;
}

export interface HistoryPoint {
  id: string;
  created_at: string;
  score: number;
  total: number;
}

export interface AuditEntry {
  ts: string;
  action: string;
  target: string;
  actor: string;
  details: Record<string, string | number | boolean | null>;
}

export interface CostRow {
  id: string;
  project_name: string;
  created_at: string;
  plan: string;
  calls: number;
  cache_hits: number;
  tokens: number;
  cost_usd: number;
  budget_refused: number;
  lines: number;
}

export interface Costs {
  plan: string;
  budget_calls: number;
  budget_tokens: number;
  price_input_per_mtok: number;
  price_output_per_mtok: number;
  total_cost_usd: number;
  total_tokens: number;
  scans: CostRow[];
}

export interface Health {
  ai_enabled: boolean;
  model: string;
  offline: boolean;
  demo_available: boolean;
}

export interface Me {
  user: { id: string; email: string; name: string };
  org: { id: string; name: string; role: Role; role_label: string; plan: PlanId; plan_name: string; features: string[] };
  organizations: { org_id: string; name: string; role: Role }[];
}

export type Role = "owner" | "admin" | "member";
export type PlanId = "free" | "pro" | "business";

export interface PlanOffer {
  id: PlanId;
  name: string;
  tagline: string;
  price_per_member_eur: number;
  monthly_scans: number | null;
  projects: number | null;
  members: number | null;
  ai_calls_per_scan: number;
  features: string[];
}

export interface Invoice {
  id: string;
  number: string;
  period: string;
  plan: PlanId;
  seats: number;
  unit_price_eur: number;
  amount_eur: number;
  status: string;
  provider: string;
  created_at: string;
}

export interface Billing {
  plan: PlanId;
  plan_name: string;
  usage: { scans_this_month: number; projects: number; members: number; pending_invitations: number };
  limits: { monthly_scans: number | null; projects: number | null; members: number | null };
  monthly_estimate_eur: number;
  catalog: PlanOffer[];
  invoices: Invoice[];
  provider: "demo" | "webhook";
  can_manage: boolean;
}

export interface OrgDetails {
  id: string;
  name: string;
  role: Role;
  members: { id: string; email: string; name: string; role: Role; joined_at: string }[];
  invitations: { id: string; email: string; role: Role; expires_at: number; created_at: string }[];
}

export interface InvitationPreview {
  org_name: string;
  email: string;
  role: Role;
  role_label: string;
  has_account: boolean;
}

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

/** Appelé quand la session expire : l'application renvoie vers la connexion. */
let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, { credentials: "same-origin", ...init });
  if (resp.status === 401 && !url.startsWith("/api/auth/")) onUnauthorized();
  if (!resp.ok) {
    let detail = `Erreur ${resp.status}`;
    try {
      const body = await resp.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join(", ");
    } catch {
      /* réponse non JSON */
    }
    throw new ApiError(detail, resp.status);
  }
  return resp.json() as Promise<T>;
}

const send = (method: string, body?: unknown): RequestInit => ({
  method,
  headers: body === undefined ? undefined : { "Content-Type": "application/json" },
  body: body === undefined ? undefined : JSON.stringify(body),
});

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  health: () => request<Health>("/api/health"),
  // Comptes et organisation (SS-2)
  me: () => request<Me>("/api/auth/me"),
  login: (email: string, password: string) => request("/api/auth/login", send("POST", { email, password })),
  register: (body: { name: string; email: string; password: string; org_name?: string; invitation_token?: string }) =>
    request("/api/auth/register", send("POST", body)),
  logout: () => request("/api/auth/logout", send("POST")),
  requestPasswordReset: (email: string) =>
    request<{ detail: string }>("/api/auth/password-reset", send("POST", { email })),
  resetPassword: (token: string, password: string) =>
    request(`/api/auth/password-reset/${token}`, send("POST", { password })),
  switchOrg: (org_id: string) => request("/api/auth/switch-org", send("POST", { org_id })),
  org: () => request<OrgDetails>("/api/org"),
  invite: (email: string, role: Role) =>
    request<{ url: string; email: string; email_sent: boolean; email_detail: string }>(
      "/api/org/invitations", send("POST", { email, role })),
  revokeInvitation: (id: string) => request(`/api/org/invitations/${id}`, send("DELETE")),
  changeRole: (userId: string, role: Role) => request(`/api/org/members/${userId}`, send("PATCH", { role })),
  removeMember: (userId: string) => request(`/api/org/members/${userId}`, send("DELETE")),
  invitation: (token: string) => request<InvitationPreview>(`/api/invitations/${token}`),
  acceptInvitation: (token: string) => request(`/api/invitations/${token}/accept`, send("POST")),
  scans: () => request<Scan[]>("/api/scans"),
  scan: (id: string) => request<Scan>(`/api/scans/${id}`),
  history: (id: string) => request<HistoryPoint[]>(`/api/scans/${id}/history`),
  findings: (id: string) => request<Finding[]>(`/api/scans/${id}/findings`),
  finding: (id: string) => request<Finding>(`/api/findings/${id}`),
  startDemo: () => request<Scan>("/api/scans/demo", { method: "POST" }),
  upload: (file: File, projectName: string) => {
    const form = new FormData();
    form.append("file", file);
    form.append("project_name", projectName);
    return request<Scan>("/api/scans/upload", { method: "POST", body: form });
  },
  git: (url: string, branch: string, projectName: string) =>
    request<Scan>("/api/scans/git", json({ url, branch: branch || null, project_name: projectName || null })),
  snippet: (filename: string, code: string, projectName: string) =>
    request<Scan>("/api/scans/snippet", json({ filename, code, project_name: projectName })),
  dismiss: (id: string, reason: string, justification: string) =>
    request<Finding>(`/api/findings/${id}/dismiss`, json({ reason, justification })),
  audit: () => request<AuditEntry[]>("/api/audit"),
  billing: () => request<Billing>("/api/billing"),
  selectPlan: (plan: PlanId) => request<{ invoice: Invoice | null }>("/api/billing/plan", send("POST", { plan })),
  costs: () => request<Costs>("/api/costs"),
  reportUrl: (id: string, format: "pdf" | "json", options?: { preparedFor?: string; preparedBy?: string }) => {
    const params = new URLSearchParams();
    if (options?.preparedFor?.trim()) params.set("prepared_for", options.preparedFor.trim());
    if (options?.preparedBy?.trim()) params.set("prepared_by", options.preparedBy.trim());
    const query = params.toString();
    return `/api/scans/${id}/report.${format}${query ? `?${query}` : ""}`;
  },
};
