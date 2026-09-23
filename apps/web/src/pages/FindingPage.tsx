import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Finding } from "../api";
import { SeverityBadge, VerdictBadge } from "../components/Badges";
import { CodeView, DiffView } from "../components/Code";
import { KIND_LABEL, LANGUAGE_LABEL, SEVERITY_LABEL } from "../labels";

type Tab = "understand" | "fix" | "refs";

const DISMISS_REASONS = [
  { value: "false_positive", label: "Faux positif" },
  { value: "accepted_risk", label: "Risque accepté" },
  { value: "not_applicable", label: "Non applicable (code mort, test…)" },
];

function DismissModal({ onClose, onDone, finding }: { onClose: () => void; onDone: (f: Finding) => void; finding: Finding }) {
  const [reason, setReason] = useState("false_positive");
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      onDone(await api.dismiss(finding.id, reason, justification));
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal stack" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <h2>Ignorer cette alerte</h2>
        <p className="secondary small" style={{ margin: 0 }}>
          L'alerte sera masquée dans les prochaines analyses de ce projet. L'action est tracée dans le journal d'audit.
        </p>
        <label className="field">
          Motif
          <select value={reason} onChange={(e) => setReason(e.target.value)}>
            {DISMISS_REASONS.map((r) => (
              <option key={r.value} value={r.value}>{r.label}</option>
            ))}
          </select>
        </label>
        <label className="field">
          Justification (obligatoire)
          <textarea
            style={{ minHeight: 90, fontFamily: "inherit", fontSize: 14 }}
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            placeholder="Ex. : la valeur provient d'une constante interne, jamais d'une saisie utilisateur."
          />
        </label>
        {error && <div className="error small">{error}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn btn-ghost" onClick={onClose}>Annuler</button>
          <button className="btn btn-primary" disabled={busy || justification.trim().length < 10} onClick={submit}>
            Confirmer
          </button>
        </div>
      </div>
    </div>
  );
}

export default function FindingPage() {
  const { scanId = "", findingId = "" } = useParams();
  const navigate = useNavigate();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [siblings, setSiblings] = useState<Finding[]>([]);
  const [tab, setTab] = useState<Tab>("understand");
  const [showDismiss, setShowDismiss] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setFinding(null);
    api.finding(findingId).then(setFinding).catch((e) => setError((e as Error).message));
  }, [findingId]);

  useEffect(() => {
    api.findings(scanId).then(setSiblings).catch(() => setSiblings([]));
  }, [scanId]);

  // Navigation entre alertes de même statut
  const group = siblings.filter((f) => f.status === (finding?.status ?? "open"));
  const index = group.findIndex((f) => f.id === findingId);
  const prev = index > 0 ? group[index - 1] : null;
  const next = index >= 0 && index < group.length - 1 ? group[index + 1] : null;

  const go = useCallback((f: Finding | null) => f && navigate(`/scans/${scanId}/findings/${f.id}`), [navigate, scanId]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (showDismiss || (e.target as HTMLElement).closest("input, textarea, select")) return;
      if (e.key === "ArrowRight" || e.key === "j") go(next);
      if (e.key === "ArrowLeft" || e.key === "k") go(prev);
      if (e.key === "Escape") navigate(`/scans/${scanId}`);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [go, next, prev, navigate, scanId, showDismiss]);

  function flash(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(null), 1800);
  }

  if (error) return <main className="container"><div className="card error">{error}</div></main>;
  if (!finding) return <main className="container"><span className="spinner" /></main>;

  const ai = finding.ai;
  const exp = ai?.explanation;
  const fix = ai?.fix;

  return (
    <main className="container stack">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <Link to={`/scans/${scanId}`} className="small">← Retour au tableau de bord</Link>
        <div className="row small secondary">
          <button className="btn" disabled={!prev} onClick={() => go(prev)} title="Alerte précédente (←)">←</button>
          <span>{index >= 0 ? `${index + 1} / ${group.length}` : ""}</span>
          <button className="btn" disabled={!next} onClick={() => go(next)} title="Alerte suivante (→)">→</button>
          <span className="muted"><kbd>←</kbd> <kbd>→</kbd> pour naviguer</span>
        </div>
      </div>

      <div className="card stack" style={{ gap: 10 }}>
        <div className="row">
          <SeverityBadge severity={finding.severity} />
          {finding.severity !== finding.raw_severity && (
            <span className="small muted">(initialement {SEVERITY_LABEL[finding.raw_severity].toLowerCase()})</span>
          )}
          <span className="tag">{KIND_LABEL[finding.kind]}</span>
          {finding.cwe && <span className="tag">{finding.cwe}</span>}
          {finding.owasp && <span className="tag">{finding.owasp}</span>}
          <span className="tag">{LANGUAGE_LABEL[finding.language] ?? finding.language}</span>
          {ai && <VerdictBadge ai={ai} />}
        </div>
        <h1>{finding.title}</h1>
        <div className="mono secondary small">{finding.file}:{finding.start_line}</div>
        {finding.kind === "ai" && (
          <div className="ai-note">
            <span aria-hidden>✦</span>
            <span>
              <strong>Détectée par la revue IA du fichier.</strong> Aucune règle statique ne couvre ce type de faille
              logique : elle a été confirmée par une seconde analyse du contexte.
            </span>
          </div>
        )}
        {finding.status === "false_positive" && ai && (
          <div className="ai-note"><span aria-hidden>✕</span><span><strong>Écartée par l'IA :</strong> {ai.reason}</span></div>
        )}
        {finding.status === "dismissed" && (
          <div className="ai-note"><span aria-hidden>⊘</span><span><strong>Ignorée :</strong> {finding.dismiss_justification}</span></div>
        )}
      </div>

      <div className="detail-layout">
        <div className="stack">
          <CodeView
            file={finding.file}
            language={finding.language}
            code={finding.snippet}
            startLine={finding.snippet_start_line}
            highlightFrom={finding.start_line}
            highlightTo={finding.end_line}
          />
          {finding.secret && (
            <div className="ai-note">
              <span aria-hidden>🔒</span>
              <span>
                {finding.secret.secret_type} détecté(e) : <span className="mono">{finding.secret.masked}</span>. La valeur
                n'est ni stockée ni transmise à l'IA ; seule une empreinte (<span className="mono">{finding.secret.fingerprint}</span>)
                est conservée.
              </span>
            </div>
          )}
          {finding.dependency && (
            <div className="card">
              <h3 style={{ marginBottom: 8 }}>
                {finding.dependency.package} {finding.dependency.version} → {finding.dependency.fixed_version ?? "pas de correctif publié"}
              </h3>
              <table className="findings-table">
                <tbody>
                  {finding.dependency.advisories.slice(0, 8).map((a) => (
                    <tr key={a.id}>
                      <td style={{ width: 110 }}><SeverityBadge severity={a.severity} /></td>
                      <td>
                        <a href={a.url} target="_blank" rel="noreferrer">{a.aliases[0] ?? a.id}</a>
                        <div className="small secondary">{a.summary}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {finding.dependency.advisories.length > 8 && (
                <div className="small muted" style={{ marginTop: 6 }}>
                  + {finding.dependency.advisories.length - 8} autres advisories
                </div>
              )}
            </div>
          )}
        </div>

        <div className="card">
          <div className="tabs" role="tablist">
            <button className={`tab ${tab === "understand" ? "active" : ""}`} onClick={() => setTab("understand")}>Comprendre</button>
            <button className={`tab ${tab === "fix" ? "active" : ""}`} onClick={() => setTab("fix")}>Corriger</button>
            <button className={`tab ${tab === "refs" ? "active" : ""}`} onClick={() => setTab("refs")}>Références</button>
          </div>

          {tab === "understand" && (
            <div>
              {exp?.definition ? (
                <>
                  <div className="explain-block"><h3>Le problème</h3><p>{exp.definition}</p></div>
                  <div className="explain-block"><h3>Comment un attaquant pourrait l'exploiter</h3><p>{exp.attack_scenario}</p></div>
                  <div className="explain-block"><h3>Impact pour l'entreprise</h3><p>{exp.business_impact}</p></div>
                  <div className="explain-block"><h3>Difficulté d'exploitation</h3><p style={{ textTransform: "capitalize" }}>{exp.difficulty}</p></div>
                  {ai?.reason && finding.kind === "sast" && (
                    <div className="explain-block"><h3>Analyse du contexte par l'IA</h3><p>{ai.reason}</p></div>
                  )}
                </>
              ) : (
                <>
                  <div className="explain-block"><h3>Le problème</h3><p>{finding.message}</p></div>
                  {finding.ai_error && (
                    <div className="ai-note" style={{ marginTop: 14 }}>
                      <span aria-hidden>ℹ</span>
                      <span>Explication détaillée indisponible : l'IA n'a pas pu être contactée pour cette alerte.</span>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {tab === "fix" && (
            <div className="stack" style={{ gap: 14 }}>
              {fix ? (
                <>
                  <p style={{ margin: 0 }}>{fix.explanation}</p>
                  <DiffView diff={fix.diff} file={finding.file} language={finding.language} />
                  <div className="row">
                    <button
                      className="btn btn-primary"
                      onClick={() => navigator.clipboard.writeText(fix.patched_code).then(() => flash("Correctif copié"))}
                    >
                      ⧉ Copier le code corrigé
                    </button>
                    {fix.syntax_valid === true && <span className="small" style={{ color: "var(--good-text)" }}>✓ Syntaxe vérifiée</span>}
                    {fix.syntax_valid === false && <span className="small error">⚠ Syntaxe à vérifier</span>}
                  </div>
                  {fix.best_practices.length > 0 && (
                    <div className="explain-block">
                      <h3>Bonnes pratiques</h3>
                      <ul className="tight">{fix.best_practices.map((b) => <li key={b}>{b}</li>)}</ul>
                    </div>
                  )}
                  <p className="small muted" style={{ margin: 0 }}>
                    Suggestion générée par IA : relisez-la et testez-la avant de l'intégrer.
                  </p>
                </>
              ) : (
                <div className="explain-block"><h3>Correctif recommandé</h3><p>{finding.fix_hint ?? "—"}</p></div>
              )}
            </div>
          )}

          {tab === "refs" && (
            <div className="stack" style={{ gap: 10 }}>
              <ul className="tight">
                {(exp?.references ?? []).map((r) => (
                  <li key={r}><a href={r} target="_blank" rel="noreferrer">{r}</a></li>
                ))}
              </ul>
              <div className="small secondary">
                Règle : <span className="mono">{finding.rule_id}</span>
                {ai && <> · Modèle : {ai.model}{ai.cached ? " (réponse en cache)" : ""}</>}
              </div>
            </div>
          )}

          {finding.status === "open" && (
            <div style={{ borderTop: "1px solid var(--border)", marginTop: 18, paddingTop: 14 }}>
              <button className="btn btn-ghost small" onClick={() => setShowDismiss(true)}>⊘ Ignorer cette alerte…</button>
            </div>
          )}
        </div>
      </div>

      {showDismiss && (
        <DismissModal
          finding={finding}
          onClose={() => setShowDismiss(false)}
          onDone={(f) => {
            setFinding(f);
            setShowDismiss(false);
            setSiblings((list) => list.map((x) => (x.id === f.id ? f : x)));
            flash("Alerte ignorée");
          }}
        />
      )}
      {toast && <div className="toast">{toast}</div>}
    </main>
  );
}
