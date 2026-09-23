import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";

/** Questionnaire de la bêta, proposé une fois après 14 jours d'utilisation (SS-21). */
export default function SurveyCard() {
  const [due, setDue] = useState(false);
  const [recommend, setRecommend] = useState<number | null>(null);
  const [useful, setUseful] = useState("");
  const [missing, setMissing] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => {
    api.surveyStatus().then((s) => setDue(s.due)).catch(() => setDue(false));
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (recommend === null) return;
    await api.sendSurvey(recommend, useful, missing);
    setDone(true);
  }

  if (!due) return null;
  if (done) return <div className="ai-note" role="status"><span aria-hidden>✓</span><span>Merci pour votre retour !</span></div>;

  return (
    <form className="card stack" onSubmit={submit} style={{ gap: 12 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Votre avis sur SecuScan (2 minutes)</h2>
        <button type="button" className="btn btn-ghost small" onClick={() => setDue(false)}>Plus tard</button>
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
    </form>
  );
}
