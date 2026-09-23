import { useEffect, useRef, useState, type DragEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, type Health, type Scan } from "../api";
import { formatDate, grade } from "../labels";

const SNIPPET_EXAMPLE = `from flask import request
import sqlite3

def find_user():
    email = request.args.get("email")
    db = sqlite3.connect("app.db")
    return db.execute("SELECT * FROM users WHERE email = '" + email + "'").fetchall()
`;

const EXTENSIONS = [
  { ext: "py", label: "Python" },
  { ext: "js", label: "JavaScript" },
  { ext: "ts", label: "TypeScript" },
  { ext: "php", label: "PHP" },
  { ext: "java", label: "Java" },
];

export default function HomePage({ health }: { health: Health | null }) {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [projectName, setProjectName] = useState("");
  const [code, setCode] = useState(SNIPPET_EXAMPLE);
  const [ext, setExt] = useState("py");
  const [gitUrl, setGitUrl] = useState("");
  const [gitBranch, setGitBranch] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.scans().then(setScans).catch(() => setScans([]));
  }, []);

  async function launch(kind: string, start: () => Promise<Scan>) {
    setBusy(kind);
    setError(null);
    try {
      const scan = await start();
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      setError((e as Error).message);
      setBusy(null);
    }
  }

  function onFile(file: File | undefined) {
    if (!file) return;
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
      <section className="hero">
        <h1>Trouvez, comprenez et corrigez les failles de votre code</h1>
        <p>
          SecuScan combine règles statiques, détection de secrets et analyse des dépendances, puis l'IA
          écarte les faux positifs, explique chaque faille en français et propose un correctif prêt à appliquer.
        </p>
      </section>

      {error && <div className="card error">{error}</div>}

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
            onClick={() => fileInput.current?.click()}
            role="button"
            tabIndex={0}
          >
            {busy === "upload" ? <span className="spinner" /> : "Déposez un .zip ici ou cliquez pour choisir"}
            <div className="small muted">100 Mo max · code supprimé après analyse</div>
          </div>
          <input
            ref={fileInput}
            type="file"
            accept=".zip"
            hidden
            onChange={(e) => onFile(e.target.files?.[0])}
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

      {scans.length > 0 && (
        <section className="card">
          <div className="card-title">
            <h2>Analyses récentes</h2>
          </div>
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
              {scans.slice(0, 12).map((s) => (
                <tr key={s.id} style={{ cursor: "pointer" }} onClick={() => navigate(`/scans/${s.id}`)}>
                  <td style={{ fontWeight: 600 }}>{s.project_name}</td>
                  <td className="secondary">{formatDate(s.created_at)}</td>
                  <td>
                    {s.status === "completed" ? "Terminée" : s.status === "failed" ? "Échec" : "En cours…"}
                  </td>
                  <td style={{ textAlign: "right" }}>{s.status === "completed" ? s.summary.total : "—"}</td>
                  <td style={{ textAlign: "right", fontWeight: 650 }}>
                    {s.score != null ? `${s.score}/100 · ${grade(s.score)}` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </main>
  );
}
