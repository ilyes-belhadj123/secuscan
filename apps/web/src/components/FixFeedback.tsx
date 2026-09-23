import { useEffect, useState } from "react";
import { api, type FixVerdict } from "../api";

const OPTIONS: { verdict: FixVerdict; label: string; icon: string }[] = [
  { verdict: "applied", label: "Je l'ai appliqué", icon: "✓" },
  { verdict: "helpful", label: "Utile", icon: "👍" },
  { verdict: "not_helpful", label: "Pas utile", icon: "👎" },
];

/** « Ce correctif vous a-t-il aidé ? » — mesure du taux de correctifs acceptés (SS-21). */
export default function FixFeedback({ findingId }: { findingId: string }) {
  const [verdict, setVerdict] = useState<FixVerdict | null>(null);
  const [comment, setComment] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setVerdict(null);
    setSaved(false);
    api.fixFeedback(findingId).then((f) => {
      if (f) {
        setVerdict(f.verdict);
        setComment(f.comment);
        setSaved(true);
      }
    }).catch(() => undefined);
  }, [findingId]);

  async function choose(v: FixVerdict) {
    setVerdict(v);
    setSaved(false);
    await api.sendFixFeedback(findingId, v, comment).then(() => setSaved(true)).catch(() => undefined);
  }

  return (
    <div className="explain-block" style={{ borderTop: "1px solid var(--border)", paddingTop: 12 }}>
      <h3>Ce correctif vous a-t-il aidé ?</h3>
      <div className="row" style={{ gap: 6 }}>
        {OPTIONS.map((o) => (
          <button key={o.verdict} type="button" className={`chip ${verdict === o.verdict ? "active" : ""}`}
                  onClick={() => choose(o.verdict)} aria-pressed={verdict === o.verdict}>
            <span aria-hidden>{o.icon}</span> {o.label}
          </button>
        ))}
        {saved && <span className="small muted">Merci, retour enregistré.</span>}
      </div>
      {verdict && (
        <div className="row" style={{ flexWrap: "nowrap", marginTop: 6 }}>
          <input value={comment} onChange={(e) => setComment(e.target.value)} maxLength={1000}
                 placeholder={verdict === "not_helpful" ? "Qu'est-ce qui n'allait pas ? (facultatif)" : "Un commentaire ? (facultatif)"}
                 aria-label="Commentaire sur le correctif" />
          <button type="button" className="btn small" onClick={() => choose(verdict)}>Envoyer</button>
        </div>
      )}
    </div>
  );
}
