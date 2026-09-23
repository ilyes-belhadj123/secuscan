import { useEffect, useState } from "react";
import { Link, Route, Routes } from "react-router-dom";
import { api, type Health } from "./api";
import FindingPage from "./pages/FindingPage";
import HomePage from "./pages/HomePage";
import ScanPage from "./pages/ScanPage";

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

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  return (
    <>
      <header className="topbar">
        <Logo />
        <span className="muted small">Analyse de sécurité du code assistée par IA</span>
        <span className="spacer" />
        {health && (
          <span className="badge" title={health.ai_enabled ? `Modèle : ${health.model}` : "Réponses IA servies depuis le cache"}>
            <span aria-hidden style={{ color: health.ai_enabled ? "var(--good)" : "var(--muted)" }}>●</span>
            {health.ai_enabled ? "IA connectée" : "IA : mode cache"}
          </span>
        )}
      </header>
      <Routes>
        <Route path="/" element={<HomePage health={health} />} />
        <Route path="/scans/:scanId" element={<ScanPage />} />
        <Route path="/scans/:scanId/findings/:findingId" element={<FindingPage />} />
      </Routes>
    </>
  );
}
