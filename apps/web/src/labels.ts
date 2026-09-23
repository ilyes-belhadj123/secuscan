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
  secret: "Secret",
  dependency: "Dépendance",
};

export const LANGUAGE_LABEL: Record<string, string> = {
  python: "Python",
  javascript: "JavaScript",
  typescript: "TypeScript",
  php: "PHP",
  java: "Java",
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

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}
