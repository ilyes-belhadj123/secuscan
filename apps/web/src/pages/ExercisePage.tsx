import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type ExerciseDetail, type SubmissionResult } from "../api";
import { CodeView } from "../components/Code";
import { LANGUAGE_LABEL } from "../labels";

export default function ExercisePage() {
  const { exerciseId = "" } = useParams();
  const [ex, setEx] = useState<ExerciseDetail | null>(null);
  const [code, setCode] = useState("");
  const [result, setResult] = useState<SubmissionResult | null>(null);
  const [hints, setHints] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tabLeaves, setTabLeaves] = useState(false); // après Échap, Tab quitte l'éditeur (navigation au clavier)

  useEffect(() => {
    setEx(null);
    setResult(null);
    setHints(0);
    api.exercise(exerciseId)
      .then((d) => { setEx(d); setCode(d.last_code ?? d.code); })
      .catch((e) => setError((e as Error).message));
  }, [exerciseId]);

  async function submit() {
    if (!ex) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.submitExercise(ex.id, code);
      setResult(r);
      setEx({ ...ex, attempts: ex.attempts + 1, passed: ex.passed || r.passed, solution: r.solution ?? ex.solution });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!ex) return <main className="container">{error ? <div className="card error">{error}</div> : <span className="spinner" />}</main>;

  return (
    <main className="container stack">
      <div>
        <Link to="/formation" className="small">← Tous les exercices</Link>
        <h1 style={{ marginTop: 4 }}>{ex.title}</h1>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          {LANGUAGE_LABEL[ex.language] ?? ex.language} · {ex.cwe} · difficulté {ex.difficulty}
          {ex.passed && <> · <strong style={{ color: "var(--good)" }}>✓ réussi</strong></>}
        </p>
      </div>

      <section className="card stack">
        <h2>Consigne</h2>
        <p style={{ margin: 0 }}>{ex.brief}</p>
        <CodeView file={ex.filename} language={ex.language} code={ex.code.replace(/\n$/, "")} startLine={1} highlightFrom={0} highlightTo={-1} />
        {ex.hints.length > 0 && (
          <div className="stack" style={{ gap: 6 }}>
            {ex.hints.slice(0, hints).map((h, i) => <div key={i} className="ai-note"><span aria-hidden>💡</span><span>{h}</span></div>)}
            {hints < ex.hints.length && (
              <button className="btn btn-ghost small" style={{ alignSelf: "flex-start" }} onClick={() => setHints(hints + 1)}>
                Afficher un indice ({hints + 1}/{ex.hints.length})
              </button>
            )}
          </div>
        )}
      </section>

      <section className="card stack">
        <div className="card-title">
          <h2>Votre correction</h2>
          <button className="btn btn-ghost small" onClick={() => { setCode(ex.code); setResult(null); }}>Repartir du code d'origine</button>
        </div>
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          spellCheck={false}
          aria-label="Code corrigé"
          style={{ minHeight: 260 }}
          onBlur={() => setTabLeaves(false)}
          onKeyDown={(e) => {
            if (e.key === "Escape") { setTabLeaves(true); return; }
            if (e.key === "Tab" && !tabLeaves && !e.shiftKey) { // indentation plutôt que changement de champ
              e.preventDefault();
              const t = e.currentTarget;
              const { selectionStart: s, selectionEnd: end } = t;
              setCode(code.slice(0, s) + "    " + code.slice(end));
              requestAnimationFrame(() => { t.selectionStart = t.selectionEnd = s + 4; });
            }
          }}
        />
        <div className="row" style={{ justifyContent: "space-between" }}>
          <span className="small muted">
            {ex.attempts} tentative(s) · le code n'est jamais exécuté · Tab indente, Échap puis Tab quitte l'éditeur
          </span>
          <button className="btn btn-primary" disabled={busy || !code.trim()} onClick={submit}>
            {busy ? <span className="spinner" /> : null} Vérifier ma correction
          </button>
        </div>
        {error && <div className="error" role="alert">{error}</div>}
      </section>

      {result && (
        <section className="card stack" role="status" style={{ borderColor: result.passed ? "var(--good)" : "var(--sev-medium)" }}>
          <h2>{result.passed ? "✓ Faille corrigée, bravo !" : "Pas encore : la correction n'est pas complète"}</h2>
          <ul className="tight" style={{ listStyle: "none", paddingLeft: 0, margin: 0 }}>
            {result.checks.map((c) => (
              <li key={c.label} style={{ color: c.ok ? undefined : "var(--sev-critical)" }}>
                <span aria-hidden>{c.ok ? "✓" : "✗"}</span> {c.label}
                {c.detail && <span className="small secondary"> — {c.detail}</span>}
              </li>
            ))}
          </ul>
          {result.ai && (
            <div className="ai-note"><span aria-hidden>🤖</span><span><strong>Avis de l'IA :</strong> {result.ai.feedback}</span></div>
          )}
        </section>
      )}

      {ex.solution && (
        <section className="card stack">
          <h2>Une solution possible</h2>
          <p className="small secondary" style={{ margin: 0 }}>Affichée une fois l'exercice réussi : d'autres corrections sont valables.</p>
          <CodeView file={ex.filename} language={ex.language} code={ex.solution.replace(/\n$/, "")} startLine={1} highlightFrom={0} highlightTo={-1} />
        </section>
      )}
    </main>
  );
}
