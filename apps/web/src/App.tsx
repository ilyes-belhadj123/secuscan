import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, type Health } from "./api";
import AuditPage from "./pages/AuditPage";
import {
  ForgotPasswordPage, InvitationPage, LoginPage, RegisterPage, ResetPasswordPage,
} from "./pages/AuthPages";
import CostsPage from "./pages/CostsPage";
import ExercisePage from "./pages/ExercisePage";
import FindingPage from "./pages/FindingPage";
import HomePage from "./pages/HomePage";
import OperatorPage from "./pages/OperatorPage";
import OrgPage from "./pages/OrgPage";
import PlanPage from "./pages/PlanPage";
import ScanPage from "./pages/ScanPage";
import SettingsPage from "./pages/SettingsPage";
import TrainingPage from "./pages/TrainingPage";
import { isAdmin, useSession } from "./session";

function Logo() {
  return (
    <Link to="/" className="brand">
      <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden>
        <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--brand)" />
        <path d="m11 16 3.5 3.5L21.5 12" stroke="#fff" strokeWidth="2.6" fill="none" strokeLinecap="round" />
      </svg>
      <span>
        <span className="brand-name">SecuScan</span>
        <span className="brand-sub">Sécurité du code · IA</span>
      </span>
    </Link>
  );
}

function OrgSwitcher() {
  const { me, refresh } = useSession();
  const navigate = useNavigate();
  if (!me) return null;
  if (me.organizations.length < 2) {
    return <Link to="/organisation" className="sidebar-org">{me.org.name}</Link>;
  }
  return (
    <select
      value={me.org.id}
      aria-label="Organisation"
      className="sidebar-select"
      onChange={async (e) => {
        try {
          await api.switchOrg(e.target.value);
          await refresh();
          navigate("/");
        } catch (err) {
          window.alert(`Changement d'organisation impossible : ${(err as Error).message}`);
        }
      }}
    >
      {me.organizations.map((o) => <option key={o.org_id} value={o.org_id}>{o.name}</option>)}
    </select>
  );
}

function NavItem({ to, children, also }: { to: string; children: ReactNode; also?: string }) {
  const { pathname } = useLocation();
  // « Tableau de bord » reste actif sur les pages d'une analyse et de ses alertes
  const active = to === "/" ? pathname === "/" || (!!also && pathname.startsWith(also)) : pathname.startsWith(to);
  return (
    <Link to={to} className={`nav-item ${active ? "active" : ""}`} aria-current={active ? "page" : undefined}>
      {children}
    </Link>
  );
}

function Sidebar({ health }: { health: Health | null }) {
  const { me, logout } = useSession();
  const navigate = useNavigate();
  if (!me) return null;
  return (
    <aside className="sidebar">
      <Logo />
      <nav className="sidebar-nav" aria-label="Navigation principale">
        <NavItem to="/" also="/scans">Tableau de bord</NavItem>
        <div className="nav-section">Analyse</div>
        <NavItem to="/formation">Formation</NavItem>
        <NavItem to="/couts">Coûts IA</NavItem>
        <div className="nav-section">Équipe</div>
        <NavItem to="/organisation">Membres</NavItem>
        <NavItem to="/offre">Offre <span className="nav-count">{me.org.plan_name}</span></NavItem>
        {isAdmin(me) && <NavItem to="/audit">Journal d'audit</NavItem>}
        {(me.can_manage_settings || me.is_operator) && <div className="nav-section">Administration</div>}
        {me.can_manage_settings && <NavItem to="/parametres">Paramètres IA</NavItem>}
        {me.is_operator && <NavItem to="/operateur">Bêta</NavItem>}
      </nav>
      <div className="sidebar-footer">
        {health && (
          <span className="status-line" title={health.ai_enabled ? `Modèle : ${health.model}` : "Réponses IA servies depuis le cache"}>
            <span aria-hidden className={`status-dot ${health.ai_enabled ? "on" : ""}`} />
            {health.ai_enabled ? "IA connectée" : "IA : mode cache"}
          </span>
        )}
        <OrgSwitcher />
        <span className="small secondary" title={me.user.email}>{me.user.name} · {me.org.role_label}</span>
        <button className="btn btn-ghost small" style={{ justifyContent: "flex-start", padding: "4px 0" }}
                onClick={async () => { await logout(); navigate("/connexion"); }}>
          Déconnexion
        </button>
      </div>
    </aside>
  );
}

export default function App() {
  const { me, loading } = useSession();
  const [health, setHealth] = useState<Health | null>(null);
  const loadHealth = useCallback(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);
  useEffect(loadHealth, [loadHealth]);

  if (loading) return <main className="container"><span className="spinner" /></main>;

  return (
    <div className={me ? "app-shell" : undefined}>
      {me ? <Sidebar health={health} /> : <header className="auth-header"><Logo /></header>}
      <div className="app-main">
      {me ? (
        <Routes>
          <Route path="/" element={<HomePage health={health} />} />
          <Route path="/scans/:scanId" element={<ScanPage />} />
          <Route path="/scans/:scanId/findings/:findingId" element={<FindingPage />} />
          <Route path="/couts" element={<CostsPage />} />
          <Route path="/formation" element={<TrainingPage />} />
          <Route path="/formation/:exerciseId" element={<ExercisePage />} />
          <Route path="/audit" element={isAdmin(me) ? <AuditPage /> : <Navigate to="/" replace />} />
          <Route path="/organisation" element={<OrgPage />} />
          <Route path="/offre" element={<PlanPage />} />
          <Route path="/operateur" element={me.is_operator ? <OperatorPage /> : <Navigate to="/" replace />} />
          <Route path="/parametres" element={me.can_manage_settings ? <SettingsPage onSaved={loadHealth} /> : <Navigate to="/" replace />} />
          <Route path="/invitation/:token" element={<InvitationPage />} />
          <Route path="/reinitialisation/:token" element={<ResetPasswordPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      ) : (
        <Routes>
          <Route path="/connexion" element={<LoginPage />} />
          <Route path="/inscription" element={<RegisterPage />} />
          <Route path="/mot-de-passe-oublie" element={<ForgotPasswordPage />} />
          <Route path="/reinitialisation/:token" element={<ResetPasswordPage />} />
          <Route path="/invitation/:token" element={<InvitationPage />} />
          <Route path="*" element={<Navigate to="/connexion" replace />} />
        </Routes>
      )}
      </div>
    </div>
  );
}
