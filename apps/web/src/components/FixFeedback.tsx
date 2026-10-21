import { useEffect, useRef, useState } from "react";
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
  const [error, setError] = useState<string | null>(null);
  const current = useRef(findingId);  // une réponse tardive ne s'applique pas à l'alerte suivante

  useEffect(() => {
    current.current = findingId;
    setVerdict(null);
    setComment("");
    setSaved(false);
    setError(null);
    api.fixFeedback(findingId).then((f) => {
      if (f && current.current === findingId) {
        setVerdict(f.verdict);
        setComment(f.comment);
        setSaved(true);
      }
    }).catch(() => undefined);
  }, [findingId]);

  async function choose(v: FixVerdict) {
    const id = findingId;
    setVerdict(v);
    setSaved(false);
    setError(null);
    try {
      await api.sendFixFeedback(id, v, comment);
      if (current.current === id) setSaved(true);
    } catch (e) {
      if (current.current === id) setError(`Retour non enregistré : ${(e as Error).message}`);
    }
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
      {error && <div className="error small">{error}</div>}
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
