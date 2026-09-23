import type { AIReview, Severity } from "../api";
import { SEVERITY_ICON, SEVERITY_LABEL, VERDICT_LABEL } from "../labels";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge sev-${severity}`}>
      <span className="sev-dot" aria-hidden>
        {SEVERITY_ICON[severity]}
      </span>
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function VerdictBadge({ ai }: { ai: AIReview }) {
  const icon = ai.verdict === "true_positive" ? "✓" : ai.verdict === "false_positive" ? "✕" : "?";
  return (
    <span className={`badge verdict-${ai.verdict}`} title={ai.reason}>
      <span aria-hidden>{icon}</span>
      {VERDICT_LABEL[ai.verdict]} · {Math.round(ai.confidence * 100)} %
    </span>
  );
}
