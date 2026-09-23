import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Costs } from "../api";
import { formatDate, formatTokens, formatUsd } from "../labels";

export default function CostsPage() {
  const [costs, setCosts] = useState<Costs | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.costs().then(setCosts).catch((e) => setError((e as Error).message));
  }, []);

  if (error) return <main className="container"><div className="card error">{error}</div></main>;
  if (!costs) return <main className="container"><span className="spinner" /></main>;

  // Moyenne calculée sur les seules analyses dont le coût a été mesuré (suivi introduit avec SS-12)
  const measured = costs.scans.filter((s) => s.cost_usd > 0);
  const average = measured.length ? costs.total_cost_usd / measured.length : 0;

  return (
    <main className="container stack">
      <div>
        <Link to="/" className="small">← Accueil</Link>
        <h1 style={{ marginTop: 4 }}>Coûts IA</h1>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          Offre <strong>{costs.plan}</strong> : jusqu'à {costs.budget_calls} appels et {formatTokens(costs.budget_tokens)} jetons
          par analyse. Au-delà, les alertes les moins graves gardent l'explication générique de leur règle. Estimation au
          tarif de {costs.price_input_per_mtok} $ / {costs.price_output_per_mtok} $ par million de jetons (entrée / sortie) ;
          les réponses en cache ne coûtent rien.
        </p>
      </div>

      <section className="kpis" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
        <div className="kpi">
          <div className="label">Coût total estimé</div>
          <div className="value">{formatUsd(costs.total_cost_usd)}</div>
          <div className="hint">{measured.length} analyse(s) au coût mesuré</div>
        </div>
        <div className="kpi">
          <div className="label">Coût moyen par analyse</div>
          <div className="value">{formatUsd(average)}</div>
          <div className="hint">hors réponses servies par le cache</div>
        </div>
        <div className="kpi">
          <div className="label">Jetons consommés</div>
          <div className="value">{formatTokens(costs.total_tokens)}</div>
          <div className="hint">toutes analyses confondues</div>
        </div>
      </section>

      <section className="card">
        <table className="findings-table">
          <thead>
            <tr>
              <th>Analyse</th>
              <th style={{ width: 170 }}>Date</th>
              <th style={{ textAlign: "right" }}>Lignes</th>
              <th style={{ textAlign: "right" }}>Appels IA</th>
              <th style={{ textAlign: "right" }}>En cache</th>
              <th style={{ textAlign: "right" }}>Jetons</th>
              <th style={{ textAlign: "right" }}>Coût estimé</th>
            </tr>
          </thead>
          <tbody>
            {costs.scans.map((s) => (
              <tr key={s.id}>
                <td>
                  <Link to={`/scans/${s.id}`}>{s.project_name}</Link>
                  {s.budget_refused > 0 && <div className="small" style={{ color: "var(--sev-high)" }}>⚠ budget atteint ({s.budget_refused} alerte(s) sans IA)</div>}
                </td>
                <td className="secondary small">{formatDate(s.created_at)}</td>
                <td className="mono small" style={{ textAlign: "right" }}>{s.lines.toLocaleString("fr-FR")}</td>
                <td className="mono small" style={{ textAlign: "right" }}>{s.calls}</td>
                <td className="mono small" style={{ textAlign: "right" }}>{s.cache_hits}</td>
                <td className="mono small" style={{ textAlign: "right" }}>{formatTokens(s.tokens)}</td>
                <td className="mono small" style={{ textAlign: "right", fontWeight: 650 }}>
                  {!s.cost_usd && s.tokens > 0 ? <span className="muted" title="Analyse antérieure au suivi des coûts">non mesuré</span> : formatUsd(s.cost_usd ?? 0)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}
