import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";

const LATER_KEY = "secuscan.surveyLater";
const LATER_DAYS = 14;

/** Questionnaire de la bêta, proposé une fois après 14 jours d'utilisation (SS-21). « Plus tard » le masque
 *  14 jours sur ce navigateur (il ne réapparaît pas à chaque retour sur l'accueil, devant un client). */
export default function SurveyCard() {
  const [due, setDue] = useState(false);
  const [recommend, setRecommend] = useState<number | null>(null);
  const [useful, setUseful] = useState("");
  const [missing, setMissing] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const later = Number(localStorage.getItem(LATER_KEY) ?? 0);
    if (Date.now() - later < LATER_DAYS * 86_400_000) return;
    api.surveyStatus().then((s) => setDue(s.due)).catch(() => setDue(false));
  }, []);

  function later() {
    localStorage.setItem(LATER_KEY, String(Date.now()));
    setDue(false);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (recommend === null) return;
    setError(null);
    try {
      await api.sendSurvey(recommend, useful, missing);
      setDone(true);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  if (!due) return null;
  if (done) return <div className="ai-note" role="status"><span aria-hidden>✓</span><span>Merci pour votre retour !</span></div>;

  return (
    <form className="card stack" onSubmit={submit} style={{ gap: 12 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Votre avis sur SecuScan (2 minutes)</h2>
        <button type="button" className="btn btn-ghost small" onClick={later}>Plus tard</button>
      </div>
      <div className="field">
        Recommanderiez-vous SecuScan à un collègue ? (0 = pas du tout, 10 = certainement)
        <div className="row" style={{ gap: 4, marginTop: 4 }}>
          {Array.from({ length: 11 }, (_, n) => (
            <button key={n} type="button" className={`chip ${recommend === n ? "active" : ""}`}
                    onClick={() => setRecommend(n)} aria-pressed={recommend === n}>{n}</button>
          ))}
        </div>
      </div>
      <label className="field">
        Qu'est-ce qui vous a été le plus utile ?
        <input value={useful} onChange={(e) => setUseful(e.target.value)} maxLength={2000} />
      </label>
      <label className="field">
        Que manque-t-il pour que vous l'utilisiez au quotidien ?
        <input value={missing} onChange={(e) => setMissing(e.target.value)} maxLength={2000} />
      </label>
      <div><button className="btn btn-primary" type="submit" disabled={recommend === null}>Envoyer</button></div>
      {error && <div className="error small">{error}</div>}
    </form>
  );
}
