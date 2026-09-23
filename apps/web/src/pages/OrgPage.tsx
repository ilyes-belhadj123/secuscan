import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type OrgDetails, type Role } from "../api";
import { formatDate } from "../labels";
import { isAdmin, useSession } from "../session";

const ROLE_LABEL: Record<Role, string> = { owner: "Propriétaire", admin: "Administrateur", member: "Membre" };

export default function OrgPage() {
  const { me, refresh, logout } = useSession();
  const navigate = useNavigate();
  const [org, setOrg] = useState<OrgDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const admin = isAdmin(me);

  const load = useCallback(() => {
    api.org().then(setOrg).catch((e) => setError((e as Error).message));
  }, []);
  useEffect(load, [load]);

  async function run(action: () => Promise<unknown>) {
    setError(null);
    try {
      await action();
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function invite(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const inv = await api.invite(email, role);
      setInviteUrl(inv.url);
      setCopied(false);
      setEmail("");
    });
  }

  async function leave() {
    if (!me) return;
    await run(() => api.removeMember(me.user.id));
    const next = await refresh();
    if (!next) {
      await logout();
      navigate("/connexion");
    }
  }

  if (!org || !me) return <main className="container">{error ? <div className="card error">{error}</div> : <span className="spinner" />}</main>;

  return (
    <main className="container stack">
      <div>
        <Link to="/" className="small">← Accueil</Link>
        <h1 style={{ marginTop: 4 }}>{org.name}</h1>
        <p className="secondary" style={{ margin: "4px 0 0" }}>
          Votre rôle : <strong>{ROLE_LABEL[org.role]}</strong>. Les analyses, alertes ignorées et rapports sont partagés entre
          les membres de l'organisation, et invisibles des autres organisations.
        </p>
      </div>
      {error && <div className="card error" role="alert">{error}</div>}

      {admin && (
        <section className="card stack">
          <h2>Inviter un membre</h2>
          <form className="row" onSubmit={invite} style={{ flexWrap: "nowrap" }}>
            <input type="email" required placeholder="prenom.nom@example.com" value={email}
                   onChange={(e) => setEmail(e.target.value)} aria-label="E-mail de la personne invitée" />
            <select value={role} onChange={(e) => setRole(e.target.value as Role)} style={{ width: "auto" }} aria-label="Rôle">
              <option value="member">Membre</option>
              <option value="admin">Administrateur</option>
            </select>
            <button className="btn btn-primary" type="submit" style={{ whiteSpace: "nowrap" }}>Créer l'invitation</button>
          </form>
          {inviteUrl && (
            <div className="ai-note" style={{ flexDirection: "column", gap: 6 }}>
              <span>Lien d'invitation (valable 7 jours, à usage unique) : transmettez-le à la personne invitée.</span>
              <div className="row" style={{ flexWrap: "nowrap" }}>
                <input readOnly value={inviteUrl} className="mono small" onFocus={(e) => e.target.select()} />
                <button className="btn" type="button"
                        onClick={() => navigator.clipboard.writeText(inviteUrl).then(() => setCopied(true))}>
                  {copied ? "✓ Copié" : "⧉ Copier"}
                </button>
              </div>
            </div>
          )}
          {org.invitations.length > 0 && (
            <table className="findings-table">
              <thead><tr><th>Invitation en attente</th><th>Rôle</th><th>Expire le</th><th /></tr></thead>
              <tbody>
                {org.invitations.map((inv) => (
                  <tr key={inv.id}>
                    <td>{inv.email}</td>
                    <td className="secondary">{ROLE_LABEL[inv.role]}</td>
                    <td className="secondary small">{formatDate(new Date(inv.expires_at * 1000).toISOString())}</td>
                    <td style={{ textAlign: "right" }}>
                      <button className="btn btn-ghost small" onClick={() => run(() => api.revokeInvitation(inv.id))}>Révoquer</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}

      <section className="card">
        <div className="card-title"><h2>Membres</h2><span className="muted small">{org.members.length} membre(s)</span></div>
        <table className="findings-table">
          <thead><tr><th>Nom</th><th>E-mail</th><th style={{ width: 200 }}>Rôle</th><th style={{ width: 170 }}>Depuis</th><th /></tr></thead>
          <tbody>
            {org.members.map((m) => {
              const isSelf = m.id === me.user.id;
              const canEdit = admin && !isSelf && (org.role === "owner" || m.role !== "owner");
              return (
                <tr key={m.id}>
                  <td style={{ fontWeight: 600 }}>{m.name}{isSelf && <span className="muted small"> (vous)</span>}</td>
                  <td className="secondary">{m.email}</td>
                  <td>
                    {canEdit ? (
                      <select value={m.role} onChange={(e) => run(() => api.changeRole(m.id, e.target.value as Role))}
                              aria-label={`Rôle de ${m.name}`}>
                        {org.role === "owner" && <option value="owner">Propriétaire</option>}
                        <option value="admin">Administrateur</option>
                        <option value="member">Membre</option>
                      </select>
                    ) : (
                      <span className="badge">{ROLE_LABEL[m.role]}</span>
                    )}
                  </td>
                  <td className="secondary small">{formatDate(m.joined_at)}</td>
                  <td style={{ textAlign: "right" }}>
                    {canEdit && <button className="btn btn-ghost small" onClick={() => run(() => api.removeMember(m.id))}>Retirer</button>}
                    {isSelf && org.role !== "owner" && <button className="btn btn-ghost small" onClick={leave}>Quitter</button>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
    </main>
  );
}
