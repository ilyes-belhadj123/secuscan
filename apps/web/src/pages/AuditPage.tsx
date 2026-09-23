import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type AuditEntry } from "../api";
import { formatDate } from "../labels";

const ACTIONS: Record<string, { label: string; icon: string }> = {
  "scan.created": { label: "Analyse lancée", icon: "▶" },
  "scan.completed": { label: "Analyse terminée", icon: "✓" },
  "scan.failed": { label: "Analyse en échec", icon: "✕" },
  "finding.dismissed": { label: "Alerte ignorée", icon: "⊘" },
  "report.exported": { label: "Rapport exporté", icon: "⤓" },
  "member.invited": { label: "Membre invité", icon: "✉" },
  "member.joined": { label: "Membre arrivé", icon: "+" },
  "member.role_changed": { label: "Rôle modifié", icon: "⇄" },
  "member.removed": { label: "Membre retiré", icon: "−" },
  "member.invitation_revoked": { label: "Invitation révoquée", icon: "⊘" },
};

const ROLES: Record<string, string> = { owner: "propriétaire", admin: "administrateur", member: "membre" };

const SOURCES: Record<string, string> = { demo: "projet de démo", upload: "archive ZIP", snippet: "extrait collé", git: "dépôt Git" };
const REASONS: Record<string, string> = {
  false_positive: "faux positif",
  accepted_risk: "risque accepté",
  not_applicable: "non applicable",
};

function describe(e: AuditEntry): string {
  const d = e.details;
  switch (e.action) {
    case "scan.created":
      return `Source : ${SOURCES[String(d.source)] ?? d.source}`;
    case "scan.completed":
      return `${d.findings} alerte(s) ouverte(s) · score ${d.score}/100`;
    case "scan.failed":
      return String(d.error ?? "");
    case "finding.dismissed":
      return `${d.title} (${d.location}) · ${REASONS[String(d.reason)] ?? d.reason} — « ${d.justification} »`;
    case "report.exported": {
      const extra = [d.prepared_for && `pour ${d.prepared_for}`, d.prepared_by && `par ${d.prepared_by}`].filter(Boolean);
      return `Format ${String(d.format).toUpperCase()}${extra.length ? ` · ${extra.join(" · ")}` : ""}`;
    }
    case "member.invited":
      return `${d.email} · ${ROLES[String(d.role)] ?? d.role}`;
    case "member.joined":
      return `${d.email} · ${ROLES[String(d.role)] ?? d.role} (${d.via})`;
    case "member.role_changed":
      return `${ROLES[String(d.from)] ?? d.from} → ${ROLES[String(d.to)] ?? d.to}`;
    case "member.removed":
      return d.self ? "Départ volontaire" : "Retiré par un administrateur";
    case "member.invitation_revoked":
      return "";
    default:
      return JSON.stringify(d);
  }
}

export default function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [filter, setFilter] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.audit().then(setEntries).catch((e) => setError((e as Error).message));
  }, []);

  const visible = useMemo(() => (entries ?? []).filter((e) => !filter || e.action === filter), [entries, filter]);

  return (
    <main className="container stack">
      <div>
        <Link to="/" className="small">← Accueil</Link>
        <h1 style={{ marginTop: 4 }}>Journal d'audit</h1>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          Traçabilité des analyses, alertes ignorées et exports de rapports. Journal en ajout seul : aucune entrée ne
          peut être modifiée ni supprimée depuis l'application.
        </p>
      </div>
      {error && <div className="card error">{error}</div>}
      <section className="card stack">
        <div className="filters">
          <button className={`chip ${!filter ? "active" : ""}`} onClick={() => setFilter(null)}>Tout</button>
          {Object.entries(ACTIONS).map(([key, a]) => (
            <button key={key} className={`chip ${filter === key ? "active" : ""}`} onClick={() => setFilter(key)}>
              {a.label}
            </button>
          ))}
        </div>
        {entries === null ? (
          <span className="spinner" />
        ) : visible.length === 0 ? (
          <p className="muted">Aucune entrée.</p>
        ) : (
          <table className="findings-table">
            <thead>
              <tr>
                <th style={{ width: 170 }}>Date</th>
                <th style={{ width: 190 }}>Action</th>
                <th style={{ width: 200 }}>Projet</th>
                <th style={{ width: 190 }}>Par</th>
                <th>Détail</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((e, i) => {
                const a = ACTIONS[e.action] ?? { label: e.action, icon: "·" };
                const scanLink = e.action.startsWith("scan.") || e.action === "report.exported";
                return (
                  <tr key={i}>
                    <td className="secondary small">{formatDate(e.ts)}</td>
                    <td>
                      <span className="badge"><span aria-hidden>{a.icon}</span>{a.label}</span>
                    </td>
                    <td>
                      {scanLink ? (
                        <Link to={`/scans/${e.target}`}>{String(e.details.project ?? e.target)}</Link>
                      ) : (
                        String(e.details.project ?? "—")
                      )}
                    </td>
                    <td className="small secondary">{e.actor || "—"}</td>
                    <td className="small">{describe(e)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
