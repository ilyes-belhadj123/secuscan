import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

/** Logo de l'organisation affiché en tête des rapports PDF (SS-18, offre Business). */
export default function LogoCard({ whiteLabel }: { whiteLabel: boolean }) {
  const [version, setVersion] = useState(() => Date.now()); // force le rechargement de l'aperçu
  const [present, setPresent] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(action: () => Promise<unknown>, presentAfter: boolean) {
    setBusy(true);
    setError(null);
    try {
      await action();
      setPresent(presentAfter);
      setVersion(Date.now());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card stack">
      <div className="card-title"><h2>Logo des rapports</h2></div>
      {!whiteLabel ? (
        <p className="secondary small" style={{ margin: 0 }}>
          Le logo en tête des rapports PDF est inclus dans l'offre Business. <Link to="/offre">Voir les offres</Link>
        </p>
      ) : (
        <>
          <p className="secondary small" style={{ margin: 0 }}>
            Affiché en tête de chaque rapport PDF à la place de SecuScan. PNG ou JPEG, 1 Mo maximum ; l'image est
            réduite et réencodée.
          </p>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <div style={{ minHeight: 56, display: "flex", alignItems: "center" }}>
              {present ? (
                <img
                  key={version}
                  src={`/api/org/logo?v=${version}`}
                  alt="Logo actuel"
                  style={{ maxHeight: 56, maxWidth: 240 }}
                  onError={() => setPresent(false)}
                />
              ) : (
                <span className="muted small">Aucun logo : les rapports portent le nom SecuScan.</span>
              )}
            </div>
            <div className="row" style={{ gap: 8 }}>
              <label className="btn" style={{ cursor: busy ? "wait" : "pointer" }}>
                {busy ? <span className="spinner" /> : null} {present ? "Remplacer" : "Ajouter un logo"}
                <input
                  type="file"
                  accept="image/png,image/jpeg"
                  hidden
                  disabled={busy}
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    e.target.value = "";
                    if (file) run(() => api.uploadLogo(file), true);
                  }}
                />
              </label>
              {present && (
                <button className="btn btn-ghost small" disabled={busy}
                        onClick={() => run(api.deleteLogo, false)}>
                  Retirer
                </button>
              )}
            </div>
          </div>
        </>
      )}
      {error && <div className="error small" role="alert">{error}</div>}
    </section>
  );
}
