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
  details: Record<string, string | number | null>;
}

export interface Health {
  ai_enabled: boolean;
  model: string;
  offline: boolean;
  demo_available: boolean;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, init);
  if (!resp.ok) {
    let detail = `Erreur ${resp.status}`;
    try {
      const body = await resp.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join(", ");
    } catch {
      /* réponse non JSON */
    }
    throw new Error(detail);
  }
  return resp.json() as Promise<T>;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  health: () => request<Health>("/api/health"),
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
  reportUrl: (id: string, format: "pdf" | "json", options?: { preparedFor?: string; preparedBy?: string }) => {
    const params = new URLSearchParams();
    if (options?.preparedFor?.trim()) params.set("prepared_for", options.preparedFor.trim());
    if (options?.preparedBy?.trim()) params.set("prepared_by", options.preparedBy.trim());
    const query = params.toString();
    return `/api/scans/${id}/report.${format}${query ? `?${query}` : ""}`;
  },
};
