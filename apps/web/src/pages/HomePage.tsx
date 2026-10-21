import { useEffect, useRef, useState, type DragEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, api, type Health, type Scan } from "../api";
import GitRepoPicker from "../components/GitRepoPicker";
import { PageHeader } from "../components/PageHeader";
import SurveyCard from "../components/SurveyCard";
import { useSession } from "../session";
import { formatDate, grade } from "../labels";

// Exemple volontairement vulnérable, prérempli dans « Coller du code »
const SNIPPET_EXAMPLE = [
  "from flask import request",
  "import sqlite3",
  "",
  "def find_user():",
  '    email = request.args.get("email")',
  '    db = sqlite3.connect("app.db")',
  // secuscan: ignore[JS-SQLI-BUILD] texte d'exemple affiché à l'utilisateur, jamais exécuté
  `    return db.execute("SELECT * FROM users WHERE email = '" + email + "'").fetchall()`,
  "",
].join("\n");

const EXTENSIONS = [
  { ext: "py", label: "Python" },
  { ext: "js", label: "JavaScript" },
  { ext: "ts", label: "TypeScript" },
  { ext: "php", label: "PHP" },
  { ext: "java", label: "Java" },
  { ext: "cs", label: "C#" },
  { ext: "go", label: "Go" },
];

const RECENT = 12;

export default function HomePage({ health }: { health: Health | null }) {
  const navigate = useNavigate();
  const { me } = useSession();
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [scansError, setScansError] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [quotaReached, setQuotaReached] = useState(false);
  // Retour du parcours OAuth GitHub / GitLab (?git=connected|denied|error)
  const [searchParams] = useSearchParams();
  const gitStatus = searchParams.get("git");
  const gitProvider = searchParams.get("provider") === "gitlab" ? "GitLab" : "GitHub";
  const gitNotice = gitStatus === "connected"
    ? { ok: true, text: `✓ Compte ${gitProvider} connecté : choisissez un dépôt dans la carte « Dépôt Git ».` }
    : gitStatus === "denied"
      ? { ok: false, text: `Connexion ${gitProvider} annulée.` }
      : gitStatus === "error"
        ? { ok: false, text: `La connexion ${gitProvider} a échoué ou a expiré : réessayez.` }
        : null;
  const [dragging, setDragging] = useState(false);
  const [projectName, setProjectName] = useState("");
  const [code, setCode] = useState(SNIPPET_EXAMPLE);
  const [ext, setExt] = useState("py");
  const [gitUrl, setGitUrl] = useState("");
  const [gitBranch, setGitBranch] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);

  // Liste rafraîchie tant qu'une analyse est en cours (son statut passe à « Terminée » sans recharger)
  const running = (scans ?? []).some((s) => s.status === "queued" || s.status === "running");
  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    function load() {
      api.scans()
        .then((list) => {
          if (cancelled) return;
          setScans(list);
          setScansError(null);
        })
        .catch((e) => !cancelled && setScansError((e as Error).message));
    }
    load();
    if (running) timer = window.setInterval(load, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [running]);

  async function launch(kind: string, start: () => Promise<Scan>) {
    setBusy(kind);
    setError(null);
    try {
      const scan = await start();
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      setError((e as Error).message);
      setQuotaReached(e instanceof ApiError && e.status === 402);
      setBusy(null);
    }
  }

  function onFile(file: File | undefined) {
    if (!file || busy) return;  // pas de second envoi pendant le premier
    const name = projectName.trim() || file.name.replace(/\.zip$/i, "");
    launch("upload", () => api.upload(file, name));
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    onFile(e.dataTransfer.files[0]);
  }

  return (
    <main className="container stack">
      <PageHeader
        title="Tableau de bord"
        subtitle={<>
          {me?.org.name} · offre {me?.org.plan_name}
          {scans ? ` · ${scans.length} analyse(s)` : ""} · règles statiques, secrets, dépendances et revue par l'IA
        </>}
        actions={
          <button className="btn btn-primary" disabled={!!busy || health?.demo_available === false}
                  onClick={() => launch("demo", api.startDemo)}>
            {busy === "demo" ? <span className="spinner" /> : null} Analyser la démo Acme Shop
          </button>
        }
      />

      <SurveyCard />
      {gitNotice && (
        <div className={gitNotice.ok ? "ai-note" : "warning-box"} role="status">
          <span>{gitNotice.text}</span>
        </div>
      )}
      {error && (
        <div className={quotaReached ? "warning-box" : "card error"} role="alert">
          {error} {quotaReached && <Link to="/offre">Voir les offres →</Link>}
        </div>
      )}

      <section className="grid-2">
        <div className="card import-card">
          <span className="icon" aria-hidden>🛒</span>
          <h2>Projet de démonstration</h2>
          <p className="secondary" style={{ margin: 0, flex: 1 }}>
            « Acme Shop » : une boutique fictive volontairement vulnérable, en Python, JavaScript/TypeScript,
            PHP et Java.
          </p>
          <button
            className="btn btn-primary"
            disabled={!!busy || health?.demo_available === false}
            onClick={() => launch("demo", api.startDemo)}
          >
            {busy === "demo" ? <span className="spinner" /> : "▶"} Analyser Acme Shop
          </button>
        </div>

        <form
          className="card import-card"
          onSubmit={(e) => {
            e.preventDefault();
            launch("git", () => api.git(gitUrl.trim(), gitBranch.trim(), ""));
          }}
        >
          <span className="icon" aria-hidden>🔗</span>
          <h2>Analyser un dépôt Git public</h2>
          <label className="field">
            URL du dépôt GitHub ou GitLab
            <input
              value={gitUrl}
              onChange={(e) => setGitUrl(e.target.value)}
              placeholder="https://github.com/organisation/projet"
              inputMode="url"
            />
          </label>
          <div className="row" style={{ flexWrap: "nowrap" }}>
            <input
              value={gitBranch}
              onChange={(e) => setGitBranch(e.target.value)}
              placeholder="Branche (par défaut)"
              aria-label="Branche"
            />
            <button className="btn btn-primary" type="submit" disabled={!!busy || !gitUrl.trim()} style={{ whiteSpace: "nowrap" }}>
              {busy === "git" ? <span className="spinner" /> : "▶"} Cloner et analyser
            </button>
          </div>
          <div className="small muted">Clone superficiel, sans exécution du code, supprimé après analyse.</div>
          <div style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
            <GitRepoPicker
              busy={!!busy}
              onLaunch={(provider, repo, branch) => launch("git", () => api.gitRepoScan(provider, repo, branch))}
            />
          </div>
        </form>

        <div className="card import-card">
          <span className="icon" aria-hidden>📦</span>
          <h2>Importer une archive ZIP</h2>
          <label className="field">
            Nom du projet
            <input value={projectName} onChange={(e) => setProjectName(e.target.value)} placeholder="Ex. Portail client" />
          </label>
          <div
            className={`dropzone ${dragging ? "active" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => !busy && fileInput.current?.click()}
            onKeyDown={(e) => {
              if ((e.key === "Enter" || e.key === " ") && !busy) {
                e.preventDefault();
                fileInput.current?.click();
              }
            }}
            role="button"
            tabIndex={0}
            aria-disabled={!!busy}
            aria-label="Choisir une archive ZIP à analyser"
          >
            {busy === "upload" ? <span className="spinner" /> : "Déposez un .zip ici ou cliquez pour choisir"}
            <div className="small muted">100 Mo max · code supprimé après analyse</div>
          </div>
          <input
            ref={fileInput}
            type="file"
            accept=".zip"
            hidden
            onChange={(e) => {
              onFile(e.target.files?.[0]);
              e.target.value = "";  // le même fichier pourra être choisi à nouveau après une erreur
            }}
          />
        </div>

        <div className="card import-card">
          <span className="icon" aria-hidden>📋</span>
          <h2>Coller du code</h2>
          <textarea value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} aria-label="Code à analyser" />
          <div className="row">
            <select value={ext} onChange={(e) => setExt(e.target.value)} style={{ width: "auto" }} aria-label="Langage">
              {EXTENSIONS.map((x) => (
                <option key={x.ext} value={x.ext}>
                  {x.label}
                </option>
              ))}
            </select>
            <button
              className="btn btn-primary"
              style={{ flex: 1, justifyContent: "center" }}
              disabled={!!busy || !code.trim()}
              onClick={() => launch("snippet", () => api.snippet(`extrait.${ext}`, code, "Extrait de code"))}
            >
              {busy === "snippet" ? <span className="spinner" /> : "▶"} Analyser l'extrait
            </button>
          </div>
        </div>
      </section>

      {scansError && <div className="card error" role="alert">Analyses récentes indisponibles : {scansError}</div>}
      {scans && scans.length === 0 && !scansError && (
        <p className="muted" style={{ textAlign: "center" }}>
          Aucune analyse pour l'instant : lancez la démonstration ou importez votre code ci-dessus.
        </p>
      )}
      {scans && scans.length > 0 && (
        <section className="card">
          <div className="card-title">
            <h2>Analyses récentes</h2>
            {scans.length > RECENT && (
              <button className="btn btn-ghost small" type="button" onClick={() => setShowAll((v) => !v)}>
                {showAll ? "Afficher les plus récentes" : `Voir toutes les analyses (${scans.length})`}
              </button>
            )}
          </div>
          <div className="table-scroll">
          <table className="scan-list">
            <thead>
              <tr>
                <th>Projet</th>
                <th>Date</th>
                <th>Statut</th>
                <th style={{ textAlign: "right" }}>Alertes</th>
                <th style={{ textAlign: "right" }}>Score</th>
              </tr>
            </thead>
            <tbody>
              {(showAll ? scans : scans.slice(0, RECENT)).map((s) => (
                <tr key={s.id} style={{ cursor: "pointer" }} onClick={() => navigate(`/scans/${s.id}`)}>
                  <td style={{ fontWeight: 600 }}>
                    <Link to={`/scans/${s.id}`} onClick={(e) => e.stopPropagation()} style={{ color: "inherit" }}>
                      {s.project_name}
                    </Link>
                  </td>
                  <td className="secondary">{formatDate(s.created_at)}</td>
                  <td>
                    {s.status === "completed" ? <span className="pill ok">Terminée</span>
                      : s.status === "failed" ? <span className="pill ko">Échec</span>
                        : <span className="pill wait">{s.status === "queued" ? "En attente" : "En cours"}</span>}
                  </td>
                  <td style={{ textAlign: "right" }}>{s.status === "completed" ? s.summary.total : "—"}</td>
                  <td style={{ textAlign: "right", fontWeight: 650 }}>
                    {s.score != null ? `${s.score}/100 · ${grade(s.score)}` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </section>
      )}
    </main>
  );
}
