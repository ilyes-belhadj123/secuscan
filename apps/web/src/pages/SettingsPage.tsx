import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, type AIModel, type AISettings } from "../api";

const CUSTOM = "__custom__";
const usd = (v: number) => (v === 0 ? "gratuit" : `${v.toLocaleString("fr-FR", { maximumFractionDigits: 2 })} $`);
const priceLabel = (m: { price_input_per_mtok: number; price_output_per_mtok: number }) =>
  m.price_input_per_mtok === 0 && m.price_output_per_mtok === 0
    ? "gratuit"
    : `${usd(m.price_input_per_mtok)} entrée · ${usd(m.price_output_per_mtok)} sortie / M jetons`;

export default function SettingsPage({ onSaved }: { onSaved: () => void }) {
  const [current, setCurrent] = useState<AISettings | null>(null);
  const [models, setModels] = useState<AIModel[] | null>(null);
  const [model, setModel] = useState("");
  const [custom, setCustom] = useState(false);
  const [search, setSearch] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.aiSettings()
      .then((s) => { setCurrent(s); setModel(s.model); })
      .catch((e) => setError((e as Error).message));
    api.aiModels().then(setModels).catch(() => setModels([]));
  }, []);

  // Modèle enregistré absent du catalogue (ou catalogue indisponible) : saisie libre
  useEffect(() => {
    if (models && current) setCustom(!models.some((m) => m.id === current.model));
  }, [models, current]);

  const groups = useMemo(() => {
    const q = search.trim().toLowerCase();
    const byProvider = new Map<string, AIModel[]>();
    for (const m of models ?? []) {
      if (q && !m.id.toLowerCase().includes(q) && !m.name.toLowerCase().includes(q) && m.id !== model) continue;
      byProvider.set(m.provider, [...(byProvider.get(m.provider) ?? []), m]);
    }
    return [...byProvider.entries()];
  }, [models, search, model]);

  const selected = models?.find((m) => m.id === model);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const saved = await api.saveAISettings(model.trim(), apiKey.trim());
      setCurrent(saved);
      setModel(saved.model);
      setApiKey("");
      setNotice(saved.key_configured ? "Connexion à OpenRouter vérifiée : réglages enregistrés et appliqués." : "Modèle enregistré.");
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!current) return <main className="container">{error ? <div className="card error">{error}</div> : <span className="spinner" />}</main>;

  return (
    <main className="container stack" style={{ maxWidth: 720 }}>
      <div>
        <h1>Paramètres</h1>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          Réglages de l'installation, communs à toutes les organisations.
        </p>
      </div>

      {current.ai_disabled && (
        <div className="warning-box">
          L'IA est coupée par la variable <span className="mono">SECUSCAN_AI_DISABLED</span> : les réglages ci-dessous
          ne seront utilisés qu'une fois cette variable retirée.
        </div>
      )}
      {error && <div className="card error" role="alert">{error}</div>}
      {notice && <div className="ai-note" role="status"><span aria-hidden>✓</span><span>{notice}</span></div>}

      <form className="card stack" onSubmit={save} autoComplete="off">
        <div className="card-title"><h2>Intelligence artificielle (OpenRouter)</h2></div>
        <label className="field">
          Clé API OpenRouter
          <input
            type="password"
            name="openrouter-key"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={current.key_configured ? `Clé enregistrée (${current.key_hint || "masquée"}) : laisser vide pour la garder` : "sk-or-..."}
            autoComplete="new-password"
            spellCheck={false}
          />
          <span className="hint muted">
            La clé n'est jamais réaffichée. Créez-la sur{" "}
            <a href="https://openrouter.ai/keys" target="_blank" rel="noreferrer">openrouter.ai/keys</a>.
          </span>
        </label>

        <div className="field stack" style={{ gap: 6 }}>
          <label className="field" htmlFor="model-select">Modèle</label>
          {models === null ? (
            <span className="small muted"><span className="spinner" /> Chargement des modèles OpenRouter…</span>
          ) : models.length === 0 ? (
            <span className="hint muted">Liste des modèles indisponible (réseau ou mode hors ligne) : saisissez l'identifiant.</span>
          ) : (
            <>
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={`Rechercher parmi ${models.length} modèles (claude, gpt, gemini, mistral…)`}
                aria-label="Rechercher un modèle"
              />
              <select
                id="model-select"
                value={custom ? CUSTOM : model}
                onChange={(e) => {
                  if (e.target.value === CUSTOM) { setCustom(true); return; }
                  setCustom(false);
                  setModel(e.target.value);
                }}
              >
                {groups.map(([provider, list]) => (
                  <optgroup key={provider} label={provider}>
                    {list.map((m) => <option key={m.id} value={m.id}>{m.name} — {priceLabel(m)}</option>)}
                  </optgroup>
                ))}
                <option value={CUSTOM}>Autre modèle (saisir l'identifiant)…</option>
              </select>
            </>
          )}
          {(custom || models?.length === 0) && (
            <input
              id={models?.length ? undefined : "model-select"}
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="fournisseur/modèle, ex. anthropic/claude-sonnet-5"
              required
              spellCheck={false}
            />
          )}
          <span className="hint muted">
            {selected
              ? <>Identifiant <span className="mono">{selected.id}</span>{selected.context_length ? ` · contexte ${selected.context_length.toLocaleString("fr-FR")} jetons` : ""}. Son tarif sera repris pour l'estimation des coûts IA.</>
              : <>Catalogue complet sur <a href="https://openrouter.ai/models" target="_blank" rel="noreferrer">openrouter.ai/models</a>. Hors catalogue, l'estimation des coûts garde le tarif actuel.</>}
          </span>
        </div>

        <div className="row" style={{ justifyContent: "space-between" }}>
          <span className="small secondary">
            <span aria-hidden style={{ color: current.ai_enabled ? "var(--good)" : "var(--muted)" }}>● </span>
            {current.ai_enabled ? `IA connectée · ${current.model} · ${priceLabel(current)}` : "IA non configurée : réponses servies depuis le cache"}
          </span>
          <button className="btn btn-primary" disabled={busy || !model.trim()}>
            {busy ? <span className="spinner" /> : null} Tester et enregistrer
          </button>
        </div>
      </form>
    </main>
  );
}
