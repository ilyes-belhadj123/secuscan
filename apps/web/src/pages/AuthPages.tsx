import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type InvitationPreview } from "../api";
import { useSession } from "../session";

function AuthCard({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <main className="container">
      <div className="card stack auth-card">
        <div>
          <h1>{title}</h1>
          {subtitle && <p className="secondary" style={{ margin: "6px 0 0" }}>{subtitle}</p>}
        </div>
        {children}
      </div>
    </main>
  );
}

const PASSWORD_HINT = "10 caractères minimum, avec majuscules, minuscules et chiffres.";

export function LoginPage() {
  const { refresh } = useSession();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(email, password);
      await refresh();
      navigate("/");
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <AuthCard title="Connexion" subtitle="Accédez aux analyses de votre organisation.">
      <form className="stack" onSubmit={submit} style={{ gap: 14 }}>
        <label className="field">
          Adresse e-mail
          <input type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="field">
          Mot de passe
          <input type="password" autoComplete="current-password" required value={password}
                 onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <div className="error small" role="alert">{error}</div>}
        <button className="btn btn-primary" type="submit" disabled={busy} style={{ justifyContent: "center" }}>
          {busy ? <span className="spinner" /> : "Se connecter"}
        </button>
      </form>
      <p className="small secondary" style={{ margin: 0 }}>
        Pas encore de compte ? <Link to="/inscription">Créer une organisation</Link>
      </p>
    </AuthCard>
  );
}

function RegisterForm({ invitation, token }: { invitation?: InvitationPreview; token?: string }) {
  const { refresh } = useSession();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [email, setEmail] = useState(invitation?.email ?? "");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.register({
        name, email, password,
        ...(invitation ? { invitation_token: token } : { org_name: orgName }),
      });
      await refresh();
      navigate("/");
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <form className="stack" onSubmit={submit} style={{ gap: 14 }}>
      <label className="field">
        Nom complet
        <input autoComplete="name" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Jane Doe" />
      </label>
      <label className="field">
        Adresse e-mail professionnelle
        <input type="email" autoComplete="email" required value={email} readOnly={!!invitation}
               onChange={(e) => setEmail(e.target.value)} placeholder="jane.doe@example.com" />
      </label>
      <label className="field">
        Mot de passe
        <input type="password" autoComplete="new-password" required value={password}
               onChange={(e) => setPassword(e.target.value)} />
        <span className="small muted" style={{ fontWeight: 400 }}>{PASSWORD_HINT}</span>
      </label>
      {!invitation && (
        <label className="field">
          Nom de votre organisation
          <input required value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Acme Corp" />
        </label>
      )}
      {error && <div className="error small" role="alert">{error}</div>}
      <button className="btn btn-primary" type="submit" disabled={busy} style={{ justifyContent: "center" }}>
        {busy ? <span className="spinner" /> : invitation ? `Rejoindre ${invitation.org_name}` : "Créer mon organisation"}
      </button>
    </form>
  );
}

export function RegisterPage() {
  return (
    <AuthCard title="Créer une organisation"
              subtitle="Vous en serez le propriétaire et pourrez inviter votre équipe.">
      <RegisterForm />
      <p className="small secondary" style={{ margin: 0 }}>
        Déjà un compte ? <Link to="/connexion">Se connecter</Link>
      </p>
    </AuthCard>
  );
}

export function InvitationPage() {
  const { token = "" } = useParams();
  const { me, refresh } = useSession();
  const navigate = useNavigate();
  const [invitation, setInvitation] = useState<InvitationPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.invitation(token).then(setInvitation).catch((e) => setError((e as Error).message));
  }, [token]);

  async function accept() {
    try {
      await api.acceptInvitation(token);
      await refresh();
      navigate("/");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (error) {
    return <AuthCard title="Invitation"><div className="error">{error}</div><Link to="/">← Accueil</Link></AuthCard>;
  }
  if (!invitation) return <main className="container"><span className="spinner" /></main>;

  const subtitle = `Vous êtes invité(e) à rejoindre ${invitation.org_name} en tant que ${invitation.role_label.toLowerCase()}.`;
  if (me) {
    const sameEmail = me.user.email === invitation.email;
    return (
      <AuthCard title="Invitation" subtitle={subtitle}>
        {sameEmail ? (
          <button className="btn btn-primary" onClick={accept} style={{ justifyContent: "center" }}>
            Rejoindre {invitation.org_name}
          </button>
        ) : (
          <div className="error small">
            Cette invitation est destinée à {invitation.email}. Vous êtes connecté(e) en tant que {me.user.email}.
          </div>
        )}
      </AuthCard>
    );
  }
  if (invitation.has_account) {
    return (
      <AuthCard title="Invitation" subtitle={subtitle}>
        <p style={{ margin: 0 }}>Un compte existe déjà pour {invitation.email} : connectez-vous puis rouvrez ce lien.</p>
        <Link className="btn btn-primary" to="/connexion" style={{ justifyContent: "center" }}>Se connecter</Link>
      </AuthCard>
    );
  }
  return (
    <AuthCard title="Invitation" subtitle={subtitle}>
      <RegisterForm invitation={invitation} token={token} />
    </AuthCard>
  );
}
