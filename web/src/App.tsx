import { FormEvent, useEffect, useRef, useState } from "react";
import {
  ApiError,
  api,
  type BootstrapState,
  type DeploymentState,
  type FoundationStatus,
  type Overview,
  type Session,
} from "./api";
import { LiveOverview } from "./Overview";

type Phase =
  | { kind: "loading" }
  | { kind: "bootstrap"; bootstrap: BootstrapState }
  | { kind: "bootstrap-expired" }
  | { kind: "login"; message?: string }
  | { kind: "ready"; session: Session; deployment: DeploymentState; status: FoundationStatus; overview: Overview }
  | { kind: "fatal"; message: string };

const CLI = '"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor"';

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "The local monitor could not complete this request.";
}

function isSessionLoss(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 401 || error.code === "authentication_required");
}

function authErrorMessage(error: unknown, action: "setup" | "login" | "logout"): string {
  if (error instanceof ApiError && (error.code === "login_rate_limited" || error.status === 429)) {
    return "Too many sign-in attempts. Wait before trying again.";
  }
	if (action === "setup") return "Administrator setup failed. Retry the local setup handoff and try again.";
  if (action === "login") return "Sign-in failed. Check the username and password.";
  return "Sign out failed. Check the local monitor status and try again.";
}

export default function App() {
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    void start();
  }, []);

  useEffect(() => {
    if (phase.kind !== "loading") headingRef.current?.focus();
  }, [phase.kind]);

  async function start() {
    setPhase({ kind: "loading" });
    try {
      const bootstrap = await api.bootstrapState();
      if (bootstrap.state === "required") {
        setPhase({ kind: "bootstrap", bootstrap });
        return;
      }
      if (bootstrap.state === "expired") {
        setPhase({ kind: "bootstrap-expired" });
        return;
      }
      try {
        const session = await api.session();
        await openFoundation(session);
      } catch (error) {
        if (isSessionLoss(error)) {
          setPhase({ kind: "login" });
          return;
        }
        throw error;
      }
    } catch (error) {
      setPhase({ kind: "fatal", message: errorMessage(error) });
    }
  }

  async function openFoundation(session: Session) {
    try {
      const [deployment, status, overview] = await Promise.all([api.deploymentState(), api.status(), api.overview()]);
      setPhase({ kind: "ready", session, deployment, status, overview });
    } catch (error) {
      if (isSessionLoss(error)) {
        setPhase({ kind: "login", message: "Your session ended. Sign in again." });
        return;
      }
      setPhase({ kind: "fatal", message: errorMessage(error) });
    }
  }

  return (
    <div className="page-shell">
      <header className="brand-bar" aria-label="Product">
        <span className="brand-mark" aria-hidden="true">LM</span>
        <span>LLM Monitor</span>
      </header>
      <main className="main-content">
        {phase.kind === "loading" && <Loading />}
        {phase.kind === "bootstrap" && (
          <Bootstrap
            headingRef={headingRef}
            expiresMs={phase.bootstrap.expires_ms}
            onAuthenticated={openFoundation}
            onExpired={() => setPhase({ kind: "bootstrap-expired" })}
            onConfigured={() => setPhase({ kind: "login", message: "Administrator setup is complete. Sign in." })}
          />
        )}
        {phase.kind === "bootstrap-expired" && (
          <BootstrapExpired headingRef={headingRef} onRetry={start} />
        )}
        {phase.kind === "login" && (
          <Login headingRef={headingRef} message={phase.message} onAuthenticated={openFoundation} />
        )}
        {phase.kind === "ready" && (
          <Foundation
            headingRef={headingRef}
            phase={phase}
            onSessionLost={() => setPhase({ kind: "login", message: "Your session ended. Sign in again." })}
            onSignedOut={() => setPhase({ kind: "login", message: "Signed out." })}
          />
        )}
        {phase.kind === "fatal" && (
          <section className="card compact-card">
            <h1 ref={headingRef} tabIndex={-1}>Cannot reach the monitor</h1>
            <p role="alert">{phase.message}</p>
            <p>Run <code>{CLI} status</code> in Terminal for local diagnostics.</p>
            <button type="button" onClick={() => void start()}>Try again</button>
          </section>
        )}
      </main>
    </div>
  );
}

function Loading() {
  return <p className="loading" role="status" aria-live="polite">Connecting to the local monitor…</p>;
}

type AuthProps = {
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  onAuthenticated: (session: Session) => Promise<void>;
};

function Bootstrap({ headingRef, expiresMs, onAuthenticated, onExpired, onConfigured }: AuthProps & { expiresMs: number | null; onExpired: () => void; onConfigured: () => void }) {
  const [token, setToken] = useState("");
  const [tokenExpiresMs, setTokenExpiresMs] = useState(expiresMs);
  const [tokenError, setTokenError] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function loadToken() {
    setTokenError("");
    try {
      const handoff = await api.bootstrapToken();
      setToken(handoff.token);
      setTokenExpiresMs(handoff.expires_ms);
    } catch (requestError) {
      if (requestError instanceof ApiError && (requestError.status === 410 || requestError.code === "bootstrap_expired")) {
        onExpired();
        return;
      }
      if (requestError instanceof ApiError && requestError.code === "bootstrap_already_completed") {
        onConfigured();
        return;
      }
      setToken("");
      setTokenError("The local setup handoff is not ready. Make sure the monitor is running, then retry.");
    }
  }

  useEffect(() => {
    void loadToken();
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (token.length < 32) return setError("The local setup handoff is not ready. Retry it, then create the administrator.");
    if (username.trim().length === 0) return setError("Enter an administrator username.");
    if (password.length < 12) return setError("Use a password with at least 12 characters.");
    if (password !== confirmation) return setError("The passwords do not match.");
    setBusy(true);
    try {
      const session = await api.bootstrapAdmin(token, username.trim(), password);
      setToken("");
      setPassword("");
      setConfirmation("");
      await onAuthenticated(session);
    } catch (requestError) {
      if (requestError instanceof ApiError && (requestError.status === 410 || requestError.code === "bootstrap_expired")) {
        setToken("");
        setPassword("");
        setConfirmation("");
        onExpired();
        return;
      }
      if (requestError instanceof ApiError && requestError.code === "bootstrap_already_completed") {
        onConfigured();
        return;
      }
      setError(authErrorMessage(requestError, "setup"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="auth-layout">
      <div className="card">
        <p className="eyebrow">First launch</p>
        <h1 ref={headingRef} tabIndex={-1}>Create the first administrator</h1>
        <p>Setup is ready on this Mac. Choose the local administrator credentials; the one-use handoff is handled automatically.</p>
        {tokenError ? <div className="notice" role="status"><p>{tokenError}</p><button className="secondary" type="button" onClick={() => void loadToken()} disabled={busy}>Retry setup handoff</button></div> : tokenExpiresMs !== null && <p className="muted">Setup handoff expires {formatDate(tokenExpiresMs)}.</p>}
        <form onSubmit={submit} aria-describedby="bootstrap-note">
          <label htmlFor="bootstrap-username">Administrator username</label>
          <input id="bootstrap-username" autoComplete="username" spellCheck={false} maxLength={128} value={username} onChange={(event) => setUsername(event.target.value)} required />
          <label htmlFor="bootstrap-password">Password</label>
          <input id="bootstrap-password" type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} required />
          <label htmlFor="bootstrap-confirmation">Confirm password</label>
          <input id="bootstrap-confirmation" type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} required />
          <p id="bootstrap-note" className="muted">The setup handoff and password stay in memory for this attempt. They are not placed in the URL or browser storage.</p>
          {error && <p className="form-error" role="alert">{error}</p>}
          <button type="submit" disabled={busy || token.length < 32}>{busy ? "Creating administrator…" : "Create administrator"}</button>
        </form>
      </div>
    </section>
  );
}

function BootstrapExpired({ headingRef, onRetry }: { headingRef: React.RefObject<HTMLHeadingElement | null>; onRetry: () => Promise<void> }) {
  return (
    <section className="card compact-card">
      <p className="eyebrow">First launch</p>
      <h1 ref={headingRef} tabIndex={-1}>The setup token expired</h1>
      <p>No administrator exists yet. Renew the one-use setup handoff in Terminal, then return here.</p>
      <pre><code>{CLI} admin bootstrap-renew</code></pre>
      <p>The command creates a fresh local handoff. The browser picks it up automatically; the secret is never printed.</p>
      <button type="button" onClick={() => void onRetry()}>Check again</button>
    </section>
  );
}

function Login({ headingRef, message, onAuthenticated }: AuthProps & { message?: string }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const session = await api.login(username, password);
      setPassword("");
      await onAuthenticated(session);
    } catch (requestError) {
      setError(authErrorMessage(requestError, "login"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="auth-layout">
      <div className="card compact-card">
        <p className="eyebrow">Local account</p>
        <h1 ref={headingRef} tabIndex={-1}>Sign in</h1>
        {message && <p className="notice" role="status">{message}</p>}
        <form onSubmit={submit}>
          <label htmlFor="login-username">Username</label>
          <input id="login-username" autoComplete="username" spellCheck={false} maxLength={128} value={username} onChange={(event) => setUsername(event.target.value)} required autoFocus />
          <label htmlFor="login-password">Password</label>
          <input id="login-password" type="password" autoComplete="current-password" maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} required />
          {error && <p className="form-error" role="alert">{error}</p>}
          <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>
        <p className="muted">For local diagnostics, run <code>{CLI} status</code> in Terminal.</p>
      </div>
    </section>
  );
}

function Foundation({
  headingRef,
  phase,
  onSessionLost,
  onSignedOut,
}: {
  headingRef: React.RefObject<HTMLHeadingElement | null>;
  phase: Extract<Phase, { kind: "ready" }>;
  onSessionLost: () => void;
  onSignedOut: () => void;
}) {
  const [logoutError, setLogoutError] = useState("");
  const [busy, setBusy] = useState(false);

  async function logout() {
    setLogoutError("");
    setBusy(true);
    try {
      await api.logout(phase.session.csrf_token);
      onSignedOut();
    } catch (error) {
      if (isSessionLoss(error)) onSessionLost();
      else setLogoutError(authErrorMessage(error, "logout"));
    } finally {
      setBusy(false);
    }
  }

  const recovery = phase.deployment.recovery_state;
  return (
    <div className="foundation">
      <div className="signed-in-bar">
        <span>Signed in as <strong>{phase.session.user.name}</strong> · {phase.session.user.role}</span>
        <button className="secondary" type="button" onClick={() => void logout()} disabled={busy}>{busy ? "Signing out…" : "Sign out"}</button>
      </div>
      {logoutError && <p className="form-error" role="alert">{logoutError}</p>}
      <section className="intro">
        <p className="eyebrow">RMT monitor</p>
        <h1 ref={headingRef} tabIndex={-1}>Monitor status</h1>
        <p>{phase.status.experimental_features ? "This dashboard reports retained observations from this Mac and paired remote machines." : "See this Mac’s resources and Ollama status, with history to investigate changes."} Monitoring never starts inference.</p>
      </section>

      {recovery !== "normal" && (
        <section className="warning-card" role="status">
          <h2>Recovery state needs attention</h2>
          <p>State: <code>{recovery}</code>. Mutations are {phase.deployment.mutations_allowed ? "allowed" : "paused"}.</p>
          <p>Run <code>{CLI} status</code> and follow the bundled recovery guide before changing configuration.</p>
        </section>
      )}

      <LiveOverview
        initial={phase.overview}
        initialStatus={phase.status}
        mutationAccess={{ role: phase.session.user.role, csrfToken: phase.session.csrf_token, generation: phase.deployment.deployment_generation, mutationsAllowed: phase.deployment.mutations_allowed }}
        onSessionLost={onSessionLost}
      />

      <section className="help-card" aria-labelledby="offline-help">
        <h2 id="offline-help">Offline help</h2>
        <p>The installed CLI and runbooks are available without an internet connection.</p>
        <ul>
          <li>Check services: <code>{CLI} status</code></li>
          <li>Check installation: <code>{CLI} install check --role {phase.status.experimental_features ? "local|master|collector" : "local"}</code></li>
          <li>Read the installed guide: <code>~/Library/Application Support/LLM Monitor/docs/operate.html</code></li>
        </ul>
        <p>User LaunchAgents do not run while this Mac is logged out, asleep or powered off. After login or wake, use <code>{CLI} status</code> to check them.</p>
      </section>

      <details className="deployment-details">
        <summary>Deployment details</summary>
        <dl>
          <div><dt>Deployment ID</dt><dd><code>{phase.deployment.deployment_id}</code></dd></div>
          <div><dt>Generation</dt><dd><code>{phase.deployment.deployment_generation}</code></dd></div>
          <div><dt>Session expires</dt><dd>{formatDate(phase.session.expires_ms)}</dd></div>
        </dl>
      </details>
    </div>
  );
}

function formatDate(value: number) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
