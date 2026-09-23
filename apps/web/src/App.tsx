import { useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api, type Health } from "./api";
import AuditPage from "./pages/AuditPage";
import { InvitationPage, LoginPage, RegisterPage } from "./pages/AuthPages";
import CostsPage from "./pages/CostsPage";
import FindingPage from "./pages/FindingPage";
import HomePage from "./pages/HomePage";
import OrgPage from "./pages/OrgPage";
import ScanPage from "./pages/ScanPage";
import { isAdmin, useSession } from "./session";

function Logo() {
  return (
    <Link to="/" className="logo">
      <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden>
        <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--brand)" />
        <path d="m11 16 3.5 3.5L21.5 12" stroke="#fff" strokeWidth="2.6" fill="none" strokeLinecap="round" />
      </svg>
      SecuScan
    </Link>
  );
}

function OrgSwitcher() {
  const { me, refresh } = useSession();
  const navigate = useNavigate();
  if (!me) return null;
  if (me.organizations.length < 2) {
    return <Link to="/organisation" className="small" style={{ fontWeight: 650 }}>{me.org.name}</Link>;
  }
  return (
    <select
      value={me.org.id}
      aria-label="Organisation"
      style={{ width: "auto", padding: "4px 8px" }}
      onChange={async (e) => {
        await api.switchOrg(e.target.value);
        await refresh();
        navigate("/");
      }}
    >
      {me.organizations.map((o) => <option key={o.org_id} value={o.org_id}>{o.name}</option>)}
    </select>
  );
}

function Topbar({ health }: { health: Health | null }) {
  const { me, logout } = useSession();
  const navigate = useNavigate();
  return (
    <header className="topbar">
      <Logo />
      {me ? <OrgSwitcher /> : <span className="muted small">Analyse de sécurité du code assistée par IA</span>}
      <span className="spacer" />
      {me && (
        <>
          <Link to="/couts" className="small" style={{ fontWeight: 600 }}>Coûts IA</Link>
          {isAdmin(me) && <Link to="/audit" className="small" style={{ fontWeight: 600 }}>Journal d'audit</Link>}
          <Link to="/organisation" className="small" style={{ fontWeight: 600 }}>Équipe</Link>
        </>
      )}
      {health && (
        <span className="badge" title={health.ai_enabled ? `Modèle : ${health.model}` : "Réponses IA servies depuis le cache"}>
          <span aria-hidden style={{ color: health.ai_enabled ? "var(--good)" : "var(--muted)" }}>●</span>
          {health.ai_enabled ? "IA connectée" : "IA : mode cache"}
        </span>
      )}
      {me && (
        <span className="row" style={{ gap: 8 }}>
          <span className="small secondary" title={me.user.email}>{me.user.name} · {me.org.role_label}</span>
          <button className="btn btn-ghost small" onClick={async () => { await logout(); navigate("/connexion"); }}>
            Déconnexion
          </button>
        </span>
      )}
    </header>
  );
}

export default function App() {
  const { me, loading } = useSession();
  const [health, setHealth] = useState<Health | null>(null);
  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  if (loading) return <main className="container"><span className="spinner" /></main>;

  return (
    <>
      <Topbar health={health} />
      {me ? (
        <Routes>
          <Route path="/" element={<HomePage health={health} />} />
          <Route path="/scans/:scanId" element={<ScanPage />} />
          <Route path="/scans/:scanId/findings/:findingId" element={<FindingPage />} />
          <Route path="/couts" element={<CostsPage />} />
          <Route path="/audit" element={isAdmin(me) ? <AuditPage /> : <Navigate to="/" replace />} />
          <Route path="/organisation" element={<OrgPage />} />
          <Route path="/invitation/:token" element={<InvitationPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      ) : (
        <Routes>
          <Route path="/connexion" element={<LoginPage />} />
          <Route path="/inscription" element={<RegisterPage />} />
          <Route path="/invitation/:token" element={<InvitationPage />} />
          <Route path="*" element={<Navigate to="/connexion" replace />} />
        </Routes>
      )}
    </>
  );
}
