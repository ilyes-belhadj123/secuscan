import { useEffect, useState } from "react";
import { api, type GitProvider, type GitRepo } from "../api";

/** Choix d'un dépôt (privé compris) sur un compte GitHub / GitLab connecté (SS-17). */
export default function GitRepoPicker({ onLaunch, busy }: {
  onLaunch: (provider: string, repo: string, branch: string) => void;
  busy: boolean;
}) {
  const [providers, setProviders] = useState<GitProvider[]>([]);
  const [provider, setProvider] = useState<string>("");
  const [repos, setRepos] = useState<GitRepo[] | null>(null);
  const [repo, setRepo] = useState("");
  const [branches, setBranches] = useState<string[]>([]);
  const [branch, setBranch] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = () => api.gitProviders().then((list) => {
    setProviders(list);
    const connected = list.find((p) => p.connected);
    if (connected) setProvider((current) => current || connected.id);
  }).catch(() => setProviders([]));
  useEffect(() => { load(); }, []);

  useEffect(() => {
    if (!provider) return;
    setRepos(null);
    setRepo("");
    api.gitRepos(provider).then(setRepos).catch((e) => setError((e as Error).message));
  }, [provider]);

  useEffect(() => {
    if (!provider || !repo) return;
    const selected = repos?.find((r) => r.id === repo);
    setBranch(selected?.default_branch ?? "");
    api.gitBranches(provider, repo).then(setBranches).catch(() => setBranches([]));
  }, [provider, repo, repos]);

  async function connect(id: string) {
    try {
      window.location.href = (await api.gitConnect(id)).authorize_url;
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const available = providers.filter((p) => p.configured);
  if (available.length === 0) {
    return <div className="small muted">Dépôts privés : connexion GitHub / GitLab non configurée sur ce serveur.</div>;
  }
  const connected = available.filter((p) => p.connected);

  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row" style={{ gap: 8 }}>
        {available.map((p) =>
          p.connected ? (
            <span key={p.id} className="badge" title={`Connecté en tant que ${p.login}`}>
              ✓ {p.name} · {p.login}
              <button className="btn btn-ghost small" style={{ padding: "0 4px" }}
                      onClick={() => api.gitDisconnect(p.id).then(() => { setProvider(""); setRepos(null); load(); })}>
                Déconnecter
              </button>
            </span>
          ) : (
            <button key={p.id} className="btn small" type="button" onClick={() => connect(p.id)}>
              Connecter {p.name}
            </button>
          ),
        )}
      </div>
      {connected.length > 0 && (
        <div className="row" style={{ flexWrap: "nowrap" }}>
          {connected.length > 1 && (
            <select value={provider} onChange={(e) => setProvider(e.target.value)} style={{ width: "auto" }} aria-label="Fournisseur">
              {connected.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          )}
          <select value={repo} onChange={(e) => setRepo(e.target.value)} aria-label="Dépôt" disabled={!repos}>
            <option value="">{repos ? "Choisir un dépôt…" : "Chargement…"}</option>
            {(repos ?? []).map((r) => <option key={r.id} value={r.id}>{r.private ? "🔒 " : ""}{r.name}</option>)}
          </select>
          <select value={branch} onChange={(e) => setBranch(e.target.value)} style={{ width: "auto" }} aria-label="Branche"
                  disabled={!repo}>
            {branches.length === 0 && <option value={branch}>{branch || "branche"}</option>}
            {branches.map((b) => <option key={b} value={b}>{b}</option>)}
          </select>
          <button className="btn btn-primary" type="button" disabled={busy || !repo}
                  onClick={() => onLaunch(provider, repo, branch)} style={{ whiteSpace: "nowrap" }}>
            ▶ Analyser
          </button>
        </div>
      )}
      {error && <div className="error small">{error}</div>}
    </div>
  );
}
