import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Billing, type PlanId, type PlanOffer } from "../api";
import { formatDate } from "../labels";
import { useSession } from "../session";

const eur = (v: number) => `${v.toLocaleString("fr-FR", { minimumFractionDigits: 0, maximumFractionDigits: 2 })} €`;
const limit = (v: number | null) => (v === null ? "Illimité" : v.toLocaleString("fr-FR"));

function Meter({ label, used, max }: { label: string; used: number; max: number | null }) {
  const ratio = max ? Math.min(1, used / max) : 0;
  const state = max && used >= max ? "atteint" : max && ratio >= 0.8 ? "presque atteint" : null;
  const color = state === "atteint" ? "var(--sev-critical)" : state ? "var(--sev-medium)" : "var(--brand)";
  return (
    <div className="kpi">
      <div className="label">{label}</div>
      <div className="value" style={{ fontSize: 24 }}>
        {used}
        <span className="muted" style={{ fontSize: 15, fontWeight: 600 }}> / {limit(max)}</span>
      </div>
      {max !== null && (
        <div className="progress-track" style={{ marginTop: 6 }} role="meter" aria-valuenow={used} aria-valuemax={max}>
          <div className="progress-fill" style={{ width: `${Math.max(2, ratio * 100)}%`, background: color }} />
        </div>
      )}
      {state && <div className="hint" style={{ color }}>{state === "atteint" ? "▲ Limite atteinte" : "● Limite presque atteinte"}</div>}
    </div>
  );
}

function PlanCard({ offer, current, canManage, busy, onSelect }: {
  offer: PlanOffer; current: PlanId; canManage: boolean; busy: boolean; onSelect: (p: PlanId) => void;
}) {
  const isCurrent = offer.id === current;
  return (
    <div className="card stack plan-card" style={{ gap: 12, borderColor: isCurrent ? "var(--brand)" : undefined }}>
      <div>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2>{offer.name}</h2>
          {isCurrent && <span className="badge">✓ Offre actuelle</span>}
        </div>
        <p className="secondary small" style={{ margin: "4px 0 0" }}>{offer.tagline}</p>
      </div>
      <div>
        <span className="hero-figure" style={{ fontSize: 34 }}>{offer.price_per_member_eur ? eur(offer.price_per_member_eur) : "Gratuit"}</span>
        {offer.price_per_member_eur > 0 && <span className="muted small"> HT / membre / mois</span>}
      </div>
      <ul className="tight">
        <li>{limit(offer.monthly_scans)} analyses par mois</li>
        <li>{offer.projects === null ? "Projets illimités" : `${offer.projects} projet`}</li>
        <li>{offer.members === null ? "Membres illimités" : `Jusqu'à ${offer.members} membres`}</li>
        <li>Jusqu'à {offer.ai_calls_per_scan} appels IA par analyse</li>
        {offer.features.filter((f) => f !== "Projets illimités").map((f) => <li key={f}>{f}</li>)}
      </ul>
      {canManage && !isCurrent && (
        <button className="btn btn-primary" disabled={busy} onClick={() => onSelect(offer.id)} style={{ justifyContent: "center" }}>
          Passer à {offer.name}
        </button>
      )}
    </div>
  );
}

export default function PlanPage() {
  const { refresh } = useSession();
  const [billing, setBilling] = useState<Billing | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.billing().then(setBilling).catch((e) => setError((e as Error).message));
  }, []);
  useEffect(load, [load]);

  async function select(plan: PlanId) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const { invoice } = await api.selectPlan(plan);
      setNotice(invoice ? `Offre modifiée. Facture ${invoice.number} émise (${eur(invoice.amount_eur)} HT).` : "Offre modifiée.");
      await refresh();
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!billing) return <main className="container">{error ? <div className="card error">{error}</div> : <span className="spinner" />}</main>;
  const u = billing.usage;

  return (
    <main className="container stack">
      <div>
        <Link to="/" className="small">← Accueil</Link>
        <h1 style={{ marginTop: 4 }}>Offre et facturation</h1>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          Offre actuelle : <strong>{billing.plan_name}</strong>
          {billing.monthly_estimate_eur > 0 && <> · estimation mensuelle {eur(billing.monthly_estimate_eur)} HT</>}.
          {!billing.can_manage && " Seul le propriétaire de l'organisation peut changer d'offre."}
        </p>
      </div>

      {billing.provider === "demo" && (
        <div className="warning-box">
          <strong>Mode démo</strong> : aucun paiement n'est encaissé. Un changement d'offre est appliqué immédiatement et
          produit une facture pro forma. Tarifs indicatifs, à valider.
        </div>
      )}
      {error && <div className="card error" role="alert">{error}</div>}
      {notice && <div className="ai-note" role="status"><span aria-hidden>✓</span><span>{notice}</span></div>}

      <section className="kpis" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
        <Meter label="Analyses ce mois-ci" used={u.scans_this_month} max={billing.limits.monthly_scans} />
        <Meter label="Projets" used={u.projects} max={billing.limits.projects} />
        <Meter label="Membres (invitations comprises)" used={u.members + u.pending_invitations} max={billing.limits.members} />
      </section>

      <section className="grid-3">
        {billing.catalog.map((offer) => (
          <PlanCard key={offer.id} offer={offer} current={billing.plan} canManage={billing.can_manage} busy={busy} onSelect={select} />
        ))}
      </section>

      {billing.invoices.length > 0 && (
        <section className="card">
          <div className="card-title"><h2>Factures</h2></div>
          <table className="findings-table">
            <thead>
              <tr><th>Numéro</th><th>Période</th><th>Offre</th><th style={{ textAlign: "right" }}>Membres</th>
                <th style={{ textAlign: "right" }}>Montant HT</th><th>Statut</th><th>Émise le</th></tr>
            </thead>
            <tbody>
              {billing.invoices.map((inv) => (
                <tr key={inv.id}>
                  <td className="mono small">{inv.number}</td>
                  <td>{inv.period}</td>
                  <td>{billing.catalog.find((c) => c.id === inv.plan)?.name ?? inv.plan}</td>
                  <td style={{ textAlign: "right" }}>{inv.seats} × {eur(inv.unit_price_eur)}</td>
                  <td style={{ textAlign: "right", fontWeight: 650 }}>{eur(inv.amount_eur)}</td>
                  <td className="secondary small">{inv.status}</td>
                  <td className="secondary small">{formatDate(inv.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </main>
  );
}
