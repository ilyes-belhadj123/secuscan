import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ExerciseSummary, type TeamTraining } from "../api";
import { formatDate, LANGUAGE_LABEL } from "../labels";
import { isAdmin, useSession } from "../session";

const DIFFICULTY_COLOR = { facile: "var(--good)", moyenne: "var(--sev-medium)", difficile: "var(--sev-critical)" };

function TeamProgress() {
  const [team, setTeam] = useState<TeamTraining | null>(null);
  useEffect(() => {
    api.teamTraining().then(setTeam).catch(() => setTeam(null));
  }, []);
  if (!team) return null;
  return (
    <section className="card">
      <div className="card-title"><h2>Progression de l'équipe</h2></div>
      <table className="findings-table">
        <thead>
          <tr><th>Membre</th><th style={{ textAlign: "right" }}>Exercices réussis</th>
            <th style={{ textAlign: "right" }}>Tentatives</th><th>Dernière activité</th></tr>
        </thead>
        <tbody>
          {team.members.map((m) => (
            <tr key={m.email}>
              <td>{m.name} <span className="muted small">{m.email}</span></td>
              <td style={{ textAlign: "right" }}><strong>{m.passed}</strong> / {team.total}</td>
              <td style={{ textAlign: "right" }} className="secondary">{m.attempts}</td>
              <td className="secondary small">{m.last_activity ? formatDate(m.last_activity) : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export default function TrainingPage() {
  const { me } = useSession();
  const [data, setData] = useState<{ exercises: ExerciseSummary[]; passed: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [language, setLanguage] = useState<string | null>(null);
  useEffect(() => {
    api.exercises().then(setData).catch((e) => setError((e as Error).message));
  }, []);
  const languages = useMemo(() => [...new Set((data?.exercises ?? []).map((ex) => ex.language))], [data]);

  if (!data) return <main className="container">{error ? <div className="card error">{error}</div> : <span className="spinner" />}</main>;
  const ratio = data.total ? data.passed / data.total : 0;

  return (
    <main className="container stack">
      <div>
        <Link to="/" className="small">← Accueil</Link>
        <h1 style={{ marginTop: 4 }}>Formation au code sécurisé</h1>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          Corrigez des failles réelles dans un code vulnérable. Votre correction est vérifiée par les règles de
          SecuScan (elle n'est jamais exécutée), puis commentée par l'IA.
        </p>
      </div>

      <section className="kpi">
        <div className="label">Votre progression</div>
        <div className="value" style={{ fontSize: 24 }}>
          {data.passed}<span className="muted" style={{ fontSize: 15, fontWeight: 600 }}> / {data.total} exercices réussis</span>
        </div>
        <div className="progress-track" style={{ marginTop: 6 }} role="meter" aria-valuenow={data.passed} aria-valuemax={data.total}>
          <div className="progress-fill" style={{ width: `${Math.max(2, ratio * 100)}%` }} />
        </div>
      </section>

      <div className="filters">
        <button className={`chip ${!language ? "active" : ""}`} onClick={() => setLanguage(null)} aria-pressed={!language}>Tous</button>
        {languages.map((l) => (
          <button key={l} className={`chip ${language === l ? "active" : ""}`} onClick={() => setLanguage(l)}
                  aria-pressed={language === l}>
            {LANGUAGE_LABEL[l] ?? l}
          </button>
        ))}
      </div>

      <section className="grid-3">
        {data.exercises.filter((ex) => !language || ex.language === language).map((ex) => (
          <Link key={ex.id} to={`/formation/${ex.id}`} className="card stack" style={{ gap: 8, color: "inherit", textDecoration: "none",
            borderColor: ex.passed ? "var(--good)" : undefined }}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className="badge">{LANGUAGE_LABEL[ex.language] ?? ex.language}</span>
              {ex.passed ? <span className="badge" style={{ color: "var(--good)" }}>✓ Réussi</span>
                : ex.attempts ? <span className="muted small">{ex.attempts} tentative(s)</span> : null}
            </div>
            <h3 style={{ margin: 0 }}>{ex.title}</h3>
            <span className="small secondary">
              {ex.cwe} · <span style={{ color: DIFFICULTY_COLOR[ex.difficulty] }}>●</span> {ex.difficulty}
            </span>
          </Link>
        ))}
      </section>

      {isAdmin(me) && <TeamProgress />}
    </main>
  );
}
