import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ApiError, NETWORK_ERROR, api, downloadFile, splitSourceUrl,
  type Finding, type FindingKind, type FindingStatus, type HistoryPoint, type Scan, type Severity,
} from "../api";
import { SeverityBadge, VerdictBadge } from "../components/Badges";
import { OwaspChart, ScoreHistoryChart, SeverityChart } from "../components/Charts";
import Modal from "../components/Modal";
import { PageHeader } from "../components/PageHeader";
import { useSession } from "../session";
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

function Progress({ scan, reconnecting }: { scan: Scan; reconnecting: boolean }) {
  const STEPS = scan.source === "git" ? ["Clonage du dépôt", ...BASE_STEPS] : BASE_STEPS;
  const current = STEPS.findIndex((s) => scan.stage.startsWith(s));
  const queued = scan.status === "queued";
  return (
    <div className="stack">
      <PageHeader
        back={<Link to="/" className="small">← Tableau de bord</Link>}
        title={scan.project_name}
        subtitle={queued
          ? "En file d'attente : l'analyse commence dès qu'un moteur d'analyse se libère."
          : "Analyse en cours · le code est lu sans jamais être exécuté, puis supprimé à la fin de l'analyse."}
      />
      {reconnecting && (
        <div className="warning-box" role="status">Connexion perdue, nouvelle tentative… L'analyse continue sur le serveur.</div>
      )}
      <section className="card stack" style={{ gap: 16 }}>
        <div className="card-title" style={{ marginBottom: 0 }}>
          <h2>Chaîne d'analyse</h2>
          <span className="muted small">{Math.round(scan.progress * 100)} %</span>
        </div>
        <div className="progress-track" role="progressbar" aria-valuenow={Math.round(scan.progress * 100)}>
          <div className="progress-fill" style={{ width: `${Math.max(3, scan.progress * 100)}%` }} />
        </div>
        <div className="pipeline">
          {STEPS.map((step, i) => {
            const state = current === -1 ? "" : i < current ? "done" : i === current ? "current" : "";
            return (
              <div key={step} className={`pipeline-step ${state}`}>
                <div className="step-head">
                  {state === "done" ? <span className="check" aria-hidden>✓</span>
                    : state === "current" ? <span className="spinner" aria-hidden />
                      : <span className="check pending" aria-hidden>{i + 1}</span>}
                  {step}
                </div>
                <div className="step-detail">
                  {state === "done" ? "Terminé" : state === "current" ? scan.stage : "En attente"}
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

/** Chaîne d'une analyse terminée : chaque étape et ce qu'elle a produit. */
function Pipeline({ scan }: { scan: Scan }) {
  const s = scan.summary;
  const withAi = s.ai_calls > 0 || s.ai_cache_hits > 0;
  const steps: { title: string; detail: string; warn?: boolean }[] = [
    { title: "Lecture du code", detail: `${s.files_scanned} fichiers, ${s.lines_scanned.toLocaleString("fr-FR")} lignes` },
    { title: "Secrets", detail: `${s.by_kind.secret ?? 0} secret(s) exposé(s)` },
    { title: "Règles statiques", detail: `${s.by_kind.sast ?? 0} faille(s) dans le code` },
    { title: "Dépendances", detail: `${s.by_kind.dependency ?? 0} dépendance(s) vulnérable(s)` },
    withAi
      ? { title: "Revue IA", detail: `${s.by_kind.ai ?? 0} faille(s) logique(s) · ${s.false_positives} faux positif(s) écarté(s)` }
      : { title: "Revue IA", detail: "IA non disponible : règles seules", warn: true },
    { title: "Score", detail: `${scan.score ?? 0}/100 · note ${grade(scan.score ?? 0)}` },
  ];
  return (
    <section className="card stack" style={{ gap: 16 }}>
      <h2>Chaîne d'analyse</h2>
      <div className="pipeline">
        {steps.map((step) => (
          <div key={step.title} className={`pipeline-step ${step.warn ? "warn" : "done"}`}>
            <div className="step-head">
              <span className={`check ${step.warn ? "warn" : ""}`} aria-hidden>{step.warn ? "!" : "✓"}</span>
              {step.title}
            </div>
            <div className="step-detail">{step.detail}</div>
          </div>
        ))}
      </div>
    </section>
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
  const [reconnecting, setReconnecting] = useState(false);
  const [attempt, setAttempt] = useState(0);  // « Réessayer » relance le suivi
  const [jsonState, setJsonState] = useState<"idle" | "busy" | string>("idle");

  useEffect(() => {
    let timer: number | undefined;
    let cancelled = false;
    let failures = 0;
    setScan(null);
    setFindings([]);
    setHistory([]);
    setError(null);
    async function poll() {
      try {
        const s = await api.scan(scanId);
        if (cancelled) return;
        failures = 0;
        setReconnecting(false);
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
        if (cancelled) return;
        // Coupure passagère (réseau, serveur redémarré) : on réessaie en espaçant, l'analyse continue
        if (e instanceof ApiError && (e.status === NETWORK_ERROR || e.status >= 500) && failures < 8) {
          failures += 1;
          setReconnecting(true);
          timer = window.setTimeout(poll, Math.min(10_000, 1000 * 2 ** failures));
        } else {
          setReconnecting(false);
          setError((e as Error).message);
        }
      }
    }
    poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [scanId, attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);
  const closeExport = useCallback(() => setShowExport(false), []);

  async function downloadJson() {
    setJsonState("busy");
    try {
      await downloadFile(api.reportUrl(scanId, "json"), `secuscan-${scanId}.json`);
      setJsonState("idle");
    } catch (e) {
      setJsonState((e as Error).message);
    }
  }

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

  if (error)
    return (
      <main className="container">
        <div className="card stack">
          <p className="error" style={{ margin: 0 }}>{error}</p>
          <div><button className="btn" onClick={retry}>Réessayer</button></div>
        </div>
      </main>
    );
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
  if (scan.status !== "completed")
    return <main className="container"><Progress scan={scan} reconnecting={reconnecting} /></main>;
  const source = scan.source_url ? splitSourceUrl(scan.source_url) : null;

  const s = scan.summary;
  const score = scan.score ?? 0;
  const visibleIds = visible.map((v) => v.id);
  const findingUrl = (f: Finding) => `/scans/${scan.id}/findings/${f.id}`;
  const counts = {
    open: findings.filter((f) => f.status === "open").length,
    false_positive: s.false_positives,
    dismissed: s.dismissed,
  };

  return (
    <main className="container stack">
      <PageHeader
        back={<Link to="/" className="small">← Tableau de bord</Link>}
        title={scan.project_name}
        subtitle={
          <>
            {source && (
              <div>
                <a className="mono" href={source.url} target="_blank" rel="noreferrer">{source.url}</a>
                {source.branch && <> · branche <span className="mono">{source.branch}</span></>}
              </div>
            )}
            <div>
              Analysé le {formatDate(scan.completed_at ?? scan.created_at)} · {s.files_scanned} fichiers ·{" "}
              {s.lines_scanned.toLocaleString("fr-FR")} lignes · {s.duration_seconds} s ·{" "}
              {Object.entries(s.languages).map(([k, v]) => `${LANGUAGE_LABEL[k] ?? k} (${v})`).join(", ")}
            </div>
            {(s.ai_calls > 0 || s.ai_cache_hits > 0) && (
              <div>
                IA : {s.ai_calls} appel(s){s.ai_budget_calls ? ` sur ${s.ai_budget_calls} autorisés` : ""} ·{" "}
                {s.ai_cache_hits} en cache · {formatTokens(s.ai_tokens)} jetons · coût estimé{" "}
                <strong>{formatUsd(s.ai_cost_usd ?? 0)}</strong> · <Link to="/couts">détail des coûts</Link>
              </div>
            )}
          </>
        }
        actions={
          <>
            <button className="btn btn-outline" onClick={downloadJson} disabled={jsonState === "busy"}>
              {jsonState === "busy" ? <span className="spinner" /> : null} Exporter en JSON
            </button>
            <button className="btn btn-primary" onClick={() => setShowExport(true)}>Rapport PDF</button>
            {jsonState !== "idle" && jsonState !== "busy" && <span className="error small">{jsonState}</span>}
          </>
        }
      />

      <Pipeline scan={scan} />

      {(s.warnings ?? []).length > 0 && (
        <div className="warning-box" role="status">
          <strong>⚠ Limites de cette analyse</strong>
          <ul className="tight">{s.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>
      )}

      <section className="grid-2 grid-score">
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
            aria-label="Rechercher dans les alertes"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ maxWidth: 280 }}
          />
        </div>
        <div className="filters">
          {(["open", "false_positive", "dismissed"] as StatusFilter[]).map((st) => (
            <button key={st} className={`chip ${statusFilter === st ? "active" : ""}`} onClick={() => setStatusFilter(st)}
                    aria-pressed={statusFilter === st}>
              {st === "open" ? "Ouvertes" : st === "false_positive" ? "Écartées par l'IA" : "Ignorées"} ({counts[st]})
            </button>
          ))}
          <span className="muted">|</span>
          <button className={`chip ${!sevFilter ? "active" : ""}`} onClick={() => setSevFilter(null)} aria-pressed={!sevFilter}>
            Toutes sévérités
          </button>
          {SEVERITIES.map((sev) => (
            <button key={sev} className={`chip ${sevFilter === sev ? "active" : ""}`} onClick={() => setSevFilter(sev)}
                    aria-pressed={sevFilter === sev}>
              {SEVERITY_LABEL[sev]}
            </button>
          ))}
          <span className="muted">|</span>
          <button className={`chip ${!kindFilter ? "active" : ""}`} onClick={() => setKindFilter(null)} aria-pressed={!kindFilter}>
            Tous types
          </button>
          {(["sast", "ai", "secret", "dependency"] as FindingKind[]).map((k) => (
            <button key={k} className={`chip ${kindFilter === k ? "active" : ""}`} onClick={() => setKindFilter(k)}
                    aria-pressed={kindFilter === k}>
              {KIND_LABEL[k]}
            </button>
          ))}
        </div>

        {visible.length === 0 ? (
          <p className="muted">Aucune alerte pour ces filtres.</p>
        ) : (
          <div className="table-scroll">
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
                  onClick={() => navigate(findingUrl(f), { state: { ids: visibleIds } })}
                >
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td>
                    {/* Vrai lien : clavier, clic du milieu, nouvel onglet */}
                    <Link className="title" to={findingUrl(f)} state={{ ids: visibleIds }} onClick={(e) => e.stopPropagation()}>
                      {f.title}
                    </Link>
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
          </div>
        )}
      </section>
      {showExport && <ExportModal scanId={scan.id} onClose={closeExport} />}
    </main>
  );
}

const PREPARED_BY_KEY = "secuscan.preparedBy";

/** Export PDF, optionnellement en marque blanche (nom de l'ESN à la place de SecuScan). */
function ExportModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const { me } = useSession();
  const whiteLabel = me?.org.features.includes("white_label") ?? false;
  const [preparedFor, setPreparedFor] = useState("");
  const [preparedBy, setPreparedBy] = useState(() => (whiteLabel ? localStorage.getItem(PREPARED_BY_KEY) ?? "" : ""));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    setBusy(true);
    setError(null);
    localStorage.setItem(PREPARED_BY_KEY, preparedBy.trim());
    try {
      await downloadFile(api.reportUrl(scanId, "pdf", { preparedFor, preparedBy }), `secuscan-${scanId}.pdf`);
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Exporter le rapport PDF" onClose={onClose}>
        <label className="field">
          Préparé pour (client, facultatif)
          <input value={preparedFor} onChange={(e) => setPreparedFor(e.target.value)} placeholder="Ex. Acme Corp" maxLength={120} />
        </label>
        <label className="field">
          Réalisé par (votre société, facultatif)
          <input value={preparedBy} onChange={(e) => setPreparedBy(e.target.value)} placeholder="Ex. Exemple Conseil"
                 maxLength={120} disabled={!whiteLabel} />
        </label>
        <p className="small muted" style={{ margin: 0 }}>
          {whiteLabel
            ? "Si « Réalisé par » est renseigné, le rapport est en marque blanche : votre nom remplace SecuScan."
            : <>La marque blanche est incluse dans l'offre Business. <Link to="/offre">Voir les offres</Link></>}
        </p>
        {error && <p className="error small" style={{ margin: 0 }}>{error}</p>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn btn-ghost" onClick={onClose}>Annuler</button>
          <button className="btn btn-primary" onClick={download} disabled={busy}>
            {busy ? <><span className="spinner" /> Préparation du rapport…</> : "⤓ Télécharger"}
          </button>
        </div>
    </Modal>
  );
}
