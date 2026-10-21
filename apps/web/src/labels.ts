import type { FindingKind, Severity } from "./api";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
};

// Icône + libellé : la sévérité n'est jamais portée par la couleur seule
export const SEVERITY_ICON: Record<Severity, string> = {
  critical: "▲",
  high: "◆",
  medium: "●",
  low: "○",
};

export const KIND_LABEL: Record<FindingKind, string> = {
  sast: "Code",
  ai: "Logique (IA)",
  secret: "Secret",
  dependency: "Dépendance",
};

export const LANGUAGE_LABEL: Record<string, string> = {
  python: "Python",
  javascript: "JavaScript",
  typescript: "TypeScript",
  php: "PHP",
  java: "Java",
  csharp: "C#",
  go: "Go",
  dockerfile: "Dockerfile",
  kubernetes: "Kubernetes",
  compose: "Docker Compose",
  terraform: "Terraform",
  config: "Configuration",
};

export const VERDICT_LABEL = {
  true_positive: "Confirmée par l'IA",
  false_positive: "Faux positif (IA)",
  uncertain: "À vérifier",
} as const;

export function grade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 50) return "C";
  if (score >= 25) return "D";
  return "E";
}

export function formatUsd(value: number): string {
  if (value > 0 && value < 0.01) return "< 0,01 $";
  return `${value.toLocaleString("fr-FR", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} $`;
}

export function formatTokens(value: number): string {
  return value >= 1000 ? `${Math.round(value / 1000).toLocaleString("fr-FR")} k` : String(value);
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

/** Motifs pour ignorer une alerte (FindingPage) et leur forme courte (journal d'audit). */
export const DISMISS_REASONS = [
  { value: "false_positive", label: "Faux positif" },
  { value: "accepted_risk", label: "Risque accepté" },
  { value: "not_applicable", label: "Non applicable (code mort, test…)" },
];
export const DISMISS_REASON_LABEL: Record<string, string> = {
  false_positive: "faux positif",
  accepted_risk: "risque accepté",
  not_applicable: "non applicable",
};

export const ROLE_LABEL: Record<"owner" | "admin" | "member", string> = {
  owner: "Propriétaire", admin: "Administrateur", member: "Membre",
};
