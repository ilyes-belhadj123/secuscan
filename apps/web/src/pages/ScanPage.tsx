import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Finding, type FindingKind, type FindingStatus, type HistoryPoint, type Scan, type Severity } from "../api";
import { SeverityBadge, VerdictBadge } from "../components/Badges";
import { OwaspChart, ScoreHistoryChart, SeverityChart } from "../components/Charts";
import {
  KIND_LABEL, LANGUAGE_LABEL, SEVERITIES, SEVERITY_LABEL, formatDate, formatTokens, formatUsd, grade,
} from "../labels";

const BASE_STEPS = [
  "Lecture du code et détection des langages",
  "Détection des secrets",
  "Analyse statique (règles)",
  "Analyse des dépendances",
  "Revue logique par l'IA",
  "Enrichissement IA",
  "Calcul du score",
];

function Progress({ scan }: { scan: Scan }) {
  const STEPS = scan.source === "git" ? ["Clonage du dépôt", ...BASE_STEPS] : BASE_STEPS;
  const current = STEPS.findIndex((s) => scan.stage.startsWith(s));
  return (
    <div className="card stack" style={{ maxWidth: 640, margin: "40px auto" }}>
      <div>
        <h2>Analyse de « {scan.project_name} » en cours</h2>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          Le code est analysé sans jamais être exécuté, puis supprimé à la fin de l'analyse.
        </p>
      </div>
      <div className="progress-track" role="progressbar" aria-valuenow={Math.round(scan.progress * 100)}>
        <div className="progress-fill" style={{ width: `${Math.max(3, scan.progress * 100)}%` }} />
      </div>
      <ol className="steps">
        {STEPS.map((step, i) => {
          const state = current === -1 ? "" : i < current ? "done" : i === current ? "current" : "";
          return (
            <li key={step} className={state}>
              <span className="step-icon">
                {state === "done" ? "✓" : state === "current" ? <span className="spinner" /> : "·"}
              </span>
              {state === "current" ? scan.stage : step}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function Kpi({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <div className="kpi">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

type StatusFilter = FindingStatus;

export default function ScanPage() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<Severity | null>(null);
  const [kindFilter, setKindFilter] = useState<FindingKind | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("open");
  const [query, setQuery] = useState("");
  const [showExport, setShowExport] = useState(false);

  useEffect(() => {
    let timer: number | undefined;
    let cancelled = false;
    async function poll() {
      try {
        const s = await api.scan(scanId);
        if (cancelled) return;
        setScan(s);
        if (s.status === "completed") {
          const [f, h] = await Promise.all([api.findings(scanId), api.history(scanId)]);
          if (!cancelled) {
            setFindings(f);
            setHistory(h);
          }
        } else if (s.status !== "failed") {
          timer = window.setTimeout(poll, 700);
        }
      } catch (e) {
        if (!cancelled) setError((e as Error).message);
      }
    }
    poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [scanId]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter(
      (f) =>
        f.status === statusFilter &&
        (!sevFilter || f.severity === sevFilter) &&
        (!kindFilter || f.kind === kindFilter) &&
        (!q || `${f.title} ${f.file} ${f.cwe} ${f.rule_id}`.toLowerCase().includes(q)),
    );
  }, [findings, sevFilter, kindFilter, statusFilter, query]);

  if (error) return <main className="container"><div className="card error">{error}</div></main>;
  if (!scan) return <main className="container"><span className="spinner" /></main>;
  if (scan.status === "failed")
    return (
      <main className="container">
        <div className="card stack">
          <h2>L'analyse a échoué</h2>
          <p className="error">{scan.error}</p>
          <Link to="/">← Retour à l'accueil</Link>
        </div>
      </main>
    );
  if (scan.status !== "completed") return <main className="container"><Progress scan={scan} /></main>;

  const s = scan.summary;
  const score = scan.score ?? 0;
  const counts = {
    open: findings.filter((f) => f.status === "open").length,
    false_positive: s.false_positives,
    dismissed: s.dismissed,
  };

  return (
    <main className="container stack">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div>
          <Link to="/" className="small">← Toutes les analyses</Link>
          <h1 style={{ marginTop: 4 }}>{scan.project_name}</h1>
          {scan.source_url && (
            <a className="small mono" href={scan.source_url.split("@")[0]} target="_blank" rel="noreferrer">
              {scan.source_url}
            </a>
          )}
          <div className="secondary small">
            Analysé le {formatDate(scan.completed_at ?? scan.created_at)} · {s.files_scanned} fichiers ·{" "}
            {s.lines_scanned.toLocaleString("fr-FR")} lignes · {s.duration_seconds} s ·{" "}
            {Object.entries(s.languages).map(([k, v]) => `${LANGUAGE_LABEL[k] ?? k} (${v})`).join(", ")}
          </div>
          {(s.ai_calls > 0 || s.ai_cache_hits > 0) && (
            <div className="secondary small">
              IA : {s.ai_calls} appel(s){s.ai_budget_calls ? ` sur ${s.ai_budget_calls} autorisés` : ""} ·{" "}
              {s.ai_cache_hits} réponse(s) en cache · {formatTokens(s.ai_tokens)} jetons · coût estimé{" "}
              <strong>{formatUsd(s.ai_cost_usd ?? 0)}</strong> · <Link to="/couts">détail des coûts</Link>
            </div>
          )}
        </div>
        <div className="row">
          <a className="btn" href={api.reportUrl(scan.id, "json")} download>
            ⤓ JSON
          </a>
          <button className="btn btn-primary" onClick={() => setShowExport(true)}>
            ⤓ Rapport PDF
          </button>
        </div>
      </div>

      {(s.warnings ?? []).length > 0 && (
        <div className="warning-box" role="status">
          <strong>⚠ Limites de cette analyse</strong>
          <ul className="tight">{s.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>
      )}

      <section className="grid-2" style={{ gridTemplateColumns: "minmax(0,0.9fr) minmax(0,1.1fr)" }}>
        <div className="card stack">
          <div className="hero-score">
            <div>
              <div className="small secondary" style={{ fontWeight: 600 }}>Score de sécurité</div>
              <div className="hero-figure">
                {score}
                <small>/100</small>
              </div>
            </div>
            <div className="grade" aria-label={`Note ${grade(score)}`}>{grade(score)}</div>
            {scan.previous_scan_id && (
              <div className="small secondary">
                Depuis l'analyse précédente :<br />
                <strong>{scan.new_findings}</strong> nouvelle(s) · <strong>{scan.fixed_findings}</strong> corrigée(s)
              </div>
            )}
          </div>
          {history.length >= 2 ? (
            <ScoreHistoryChart points={history} />
          ) : (
            <div className="ai-note">
              <span aria-hidden>ℹ</span>
              <span>
                {s.false_positives > 0
                  ? `L'IA a écarté ${s.false_positives} alerte(s) après analyse du contexte : elles n'apparaissent pas dans le score.`
                  : "Relancez une analyse après correction pour suivre l'évolution du score."}
              </span>
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-title">
            <h2>Alertes par sévérité</h2>
            <span className="muted small">{s.total} ouvertes</span>
          </div>
          <SeverityChart bySeverity={s.by_severity} onSelect={(sev) => { setStatusFilter("open"); setSevFilter(sev); }} />
        </div>
      </section>

      <section className="kpis">
        <Kpi label="Alertes critiques" value={s.by_severity.critical ?? 0} hint="à traiter en priorité" />
        <Kpi label="Failles dans le code" value={s.by_kind.sast ?? 0} hint="règles statiques" />
        <Kpi label="Failles logiques" value={s.by_kind.ai ?? 0} hint="trouvées par l'IA seule" />
        <Kpi label="Secrets exposés" value={s.by_kind.secret ?? 0} hint="valeurs jamais stockées" />
        <Kpi label="Dépendances vulnérables" value={s.by_kind.dependency ?? 0} hint="CVE connues" />
        <Kpi
          label="Faux positifs écartés"
          value={s.false_positives}
          hint={scan.ai_enabled || s.ai_cache_hits ? "par la validation IA" : "IA non disponible"}
        />
      </section>

      {Object.keys(s.by_owasp).length > 0 && (
        <section className="card">
          <div className="card-title">
            <h2>Catégories OWASP Top 10 (2025)</h2>
            <span className="muted small">alertes ouvertes par catégorie</span>
          </div>
          <OwaspChart byOwasp={s.by_owasp} />
        </section>
      )}

      <section className="card stack">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2>Alertes</h2>
          <input
            placeholder="Rechercher (fichier, CWE, règle…)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ maxWidth: 280 }}
          />
        </div>
        <div className="filters">
          {(["open", "false_positive", "dismissed"] as StatusFilter[]).map((st) => (
            <button key={st} className={`chip ${statusFilter === st ? "active" : ""}`} onClick={() => setStatusFilter(st)}>
              {st === "open" ? "Ouvertes" : st === "false_positive" ? "Écartées par l'IA" : "Ignorées"} ({counts[st]})
            </button>
          ))}
          <span className="muted">|</span>
          <button className={`chip ${!sevFilter ? "active" : ""}`} onClick={() => setSevFilter(null)}>
            Toutes sévérités
          </button>
          {SEVERITIES.map((sev) => (
            <button key={sev} className={`chip ${sevFilter === sev ? "active" : ""}`} onClick={() => setSevFilter(sev)}>
              {SEVERITY_LABEL[sev]}
            </button>
          ))}
          <span className="muted">|</span>
          <button className={`chip ${!kindFilter ? "active" : ""}`} onClick={() => setKindFilter(null)}>
            Tous types
          </button>
          {(["sast", "ai", "secret", "dependency"] as FindingKind[]).map((k) => (
            <button key={k} className={`chip ${kindFilter === k ? "active" : ""}`} onClick={() => setKindFilter(k)}>
              {KIND_LABEL[k]}
            </button>
          ))}
        </div>

        {visible.length === 0 ? (
          <p className="muted">Aucune alerte pour ces filtres.</p>
        ) : (
          <table className="findings-table">
            <thead>
              <tr>
                <th style={{ width: 110 }}>Sévérité</th>
                <th>Alerte</th>
                <th style={{ width: 110 }}>Type</th>
                <th style={{ width: 190 }}>Référence</th>
                <th style={{ width: 210 }}>Validation IA</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((f) => (
                <tr
                  key={f.id}
                  className={`clickable ${f.status !== "open" ? "faded" : ""}`}
                  onClick={() => navigate(`/scans/${scan.id}/findings/${f.id}`, { state: { ids: visible.map((v) => v.id) } })}
                >
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td>
                    <div className="title">{f.title}</div>
                    <div className="loc mono">{f.file}:{f.start_line}</div>
                  </td>
                  <td className="secondary">{KIND_LABEL[f.kind]}</td>
                  <td className="small secondary">
                    {f.cwe}
                    <br />
                    {f.owasp?.split(" – ")[0]}
                  </td>
                  <td>
                    {f.ai ? <VerdictBadge ai={f.ai} /> : <span className="muted small">{f.ai_error ? "IA indisponible" : "—"}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      {showExport && <ExportModal scanId={scan.id} onClose={() => setShowExport(false)} />}
    </main>
  );
}

const PREPARED_BY_KEY = "secuscan.preparedBy";

/** Export PDF, optionnellement en marque blanche (nom de l'ESN à la place de SecuScan). */
function ExportModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const [preparedFor, setPreparedFor] = useState("");
  const [preparedBy, setPreparedBy] = useState(() => localStorage.getItem(PREPARED_BY_KEY) ?? "");
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal stack" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <h2>Exporter le rapport PDF</h2>
        <label className="field">
          Préparé pour (client, facultatif)
          <input value={preparedFor} onChange={(e) => setPreparedFor(e.target.value)} placeholder="Ex. Acme Corp" maxLength={120} />
        </label>
        <label className="field">
          Réalisé par (votre société, facultatif)
          <input value={preparedBy} onChange={(e) => setPreparedBy(e.target.value)} placeholder="Ex. Exemple Conseil" maxLength={120} />
        </label>
        <p className="small muted" style={{ margin: 0 }}>
          Si « Réalisé par » est renseigné, le rapport est en marque blanche : votre nom remplace SecuScan.
        </p>
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn btn-ghost" onClick={onClose}>Annuler</button>
          <a
            className="btn btn-primary"
            href={api.reportUrl(scanId, "pdf", { preparedFor, preparedBy })}
            download
            onClick={() => {
              localStorage.setItem(PREPARED_BY_KEY, preparedBy.trim());
              window.setTimeout(onClose, 300);
            }}
          >
            ⤓ Télécharger
          </a>
        </div>
      </div>
    </div>
  );
}
