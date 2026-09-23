import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type OperatorDashboard } from "../api";
import { formatDate } from "../labels";

const pct = (v: number | null) => (v === null ? "—" : `${Math.round(v * 100)} %`);
const VERDICT = { applied: "Appliqué", helpful: "Utile", not_helpful: "Pas utile" } as const;
const KIND = { sast: "Code", ai: "Logique (IA)", secret: "Secret", dependency: "Dépendance" } as Record<string, string>;

function Goal({ label, value, goal, ok }: { label: string; value: string; goal: string; ok: boolean | null }) {
  return (
    <div className="kpi">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      <div className="hint" style={{ color: ok === null ? undefined : ok ? "var(--good-text)" : "var(--sev-high)" }}>
        {ok === null ? "pas encore de données" : ok ? "✓ objectif atteint" : "● objectif non atteint"} · objectif {goal}
      </div>
    </div>
  );
}

/** Tableau de bord de la bêta (SS-21), réservé à l'opérateur de la plateforme. */
export default function OperatorPage() {
  const [data, setData] = useState<OperatorDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.operator().then(setData).catch((e) => setError((e as Error).message));
  }, []);

  if (error) return <main className="container"><div className="card error">{error}</div></main>;
  if (!data) return <main className="container"><span className="spinner" /></main>;
  const t = data.totals;

  return (
    <main className="container stack">
      <div>
        <Link to="/" className="small">← Accueil</Link>
        <h1 style={{ marginTop: 4 }}>Bêta — équipes pilotes</h1>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          Indicateurs agrégés de toutes les organisations (aucun code ni contenu d'alerte). Objectifs issus du cahier des charges.
        </p>
      </div>

      <section className="kpis" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
        <Goal label="Équipes pilotes actives" value={`${t.active} / ${t.organizations}`} goal="10" ok={t.organizations ? t.active >= 10 : null} />
        <Goal label="Revenues la semaine suivante" value={String(t.returned)} goal="≥ 5" ok={t.active ? t.returned >= 5 : null} />
        <Goal label="Correctifs acceptés" value={pct(t.acceptance_rate)} goal="> 50 %"
              ok={t.acceptance_rate === null ? null : t.acceptance_rate > 0.5} />
        <div className="kpi">
          <div className="label">Recommandation (NPS)</div>
          <div className="value">{t.nps === null ? "—" : t.nps}</div>
          <div className="hint">{t.survey_answers} réponse(s) · {t.feedback} retour(s) · {t.fix_copies} copie(s)</div>
        </div>
      </section>

      <section className="card">
        <div className="card-title"><h2>Organisations</h2></div>
        <table className="findings-table">
          <thead>
            <tr><th>Organisation</th><th>Offre</th><th style={{ textAlign: "right" }}>Membres</th>
              <th style={{ textAlign: "right" }}>Analyses</th><th>Revenue</th><th>Dernière analyse</th>
              <th style={{ textAlign: "right" }}>Retours</th><th style={{ textAlign: "right" }}>Acceptés</th></tr>
          </thead>
          <tbody>
            {data.organizations.map((o) => (
              <tr key={o.name + o.created_at}>
                <td style={{ fontWeight: 600 }}>{o.name}</td>
                <td className="secondary">{o.plan}</td>
                <td style={{ textAlign: "right" }}>{o.members}</td>
                <td style={{ textAlign: "right" }}>{o.scans}</td>
                <td>{o.returned ? "✓ oui" : "—"}</td>
                <td className="secondary small">{o.last_scan ? formatDate(o.last_scan) : "—"}</td>
                <td style={{ textAlign: "right" }}>{o.feedback_total}</td>
                <td style={{ textAlign: "right", fontWeight: 650 }}>{pct(o.acceptance_rate)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="grid-2">
        <div className="card">
          <div className="card-title"><h2>Acceptation par type d'alerte</h2></div>
          <table className="findings-table">
            <tbody>
              {Object.entries(data.acceptance_by_kind).map(([kind, v]) => (
                <tr key={kind}><td>{KIND[kind] ?? kind}</td>
                  <td style={{ textAlign: "right" }}>{v.accepted} / {v.total}</td>
                  <td style={{ textAlign: "right", fontWeight: 650 }}>{pct(v.total ? v.accepted / v.total : null)}</td></tr>
              ))}
            </tbody>
          </table>
          {Object.keys(data.acceptance_by_kind).length === 0 && <p className="muted">Aucun retour pour l'instant.</p>}
        </div>
        <div className="card">
          <div className="card-title"><h2>Commentaires sur les correctifs</h2></div>
          <ul className="tight">
            {data.comments.map((c, i) => <li key={i}><strong>{VERDICT[c.verdict]}</strong> · <span className="mono small">{c.rule_id}</span> — {c.comment}</li>)}
          </ul>
          {data.comments.length === 0 && <p className="muted">Aucun commentaire pour l'instant.</p>}
        </div>
      </section>

      <section className="card">
        <div className="card-title"><h2>Questionnaire</h2><span className="muted small">proposé après 14 jours</span></div>
        {data.surveys.length === 0 ? <p className="muted">Aucune réponse pour l'instant.</p> : (
          <table className="findings-table">
            <thead><tr><th style={{ width: 90 }}>Note</th><th>Le plus utile</th><th>Ce qui manque</th><th style={{ width: 170 }}>Date</th></tr></thead>
            <tbody>
              {data.surveys.map((s, i) => (
                <tr key={i}><td style={{ fontWeight: 650 }}>{s.recommend}/10</td><td>{s.useful || "—"}</td>
                  <td>{s.missing || "—"}</td><td className="secondary small">{formatDate(s.created_at)}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
