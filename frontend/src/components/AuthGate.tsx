import { useState, type FormEvent } from "react";
import { KeyRound, Loader2, LogOut, ShieldCheck } from "lucide-react";
import { api } from "../api";
import type { AuthConfigResponse, SsoPrincipal } from "../types";

interface AuthGateProps {
  mode: "bootstrap" | "login" | "change_password";
  authConfig: AuthConfigResponse | null;
  principal?: SsoPrincipal | null;
  initialError?: string | null;
  onAuthenticated: () => Promise<void>;
  onLogout?: () => Promise<void>;
}

function mapAuthErrorMessage(raw: string | null | undefined): string | null {
  if (!raw) return null;
  switch (raw) {
    case "not_invited":
      return "Your Google account has not been invited yet. Ask a workspace admin to add your email under Settings -> Users & Teams.";
    case "account_disabled":
      return "Your account is currently disabled. Contact a workspace administrator.";
    case "google_not_enabled":
      return "Google Sign-In is disabled for your account. Sign in with your email and password instead.";
    case "google_disabled":
      return "Google Sign-In is not enabled on this server.";
    case "google_failed":
      return "Google Sign-In failed or expired. Please try again.";
    default:
      return raw;
  }
}

export function AuthGate({
  mode,
  authConfig,
  principal,
  initialError,
  onAuthenticated,
  onLogout,
}: AuthGateProps) {
  const [email, setEmail] = useState(principal?.email ?? "");
  const [displayName, setDisplayName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(() => mapAuthErrorMessage(initialError));

  const googleEnabled =
    Boolean(authConfig?.google_auth_enabled) && authConfig?.auth_mode === "hybrid";

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (mode === "bootstrap") {
      if (password !== confirmPassword) {
        setError("Passwords do not match.");
        return;
      }
      setSubmitting(true);
      try {
        await api.bootstrapAdmin({
          email: email.trim(),
          display_name: displayName.trim(),
          password,
        });
        await onAuthenticated();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to initialize admin account.");
      } finally {
        setSubmitting(false);
      }
      return;
    }

    if (mode === "change_password") {
      if (password !== confirmPassword) {
        setError("New passwords do not match.");
        return;
      }
      setSubmitting(true);
      try {
        await api.changePassword({
          ...(currentPassword ? { current_password: currentPassword } : {}),
          new_password: password,
        });
        await onAuthenticated();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to update password.");
      } finally {
        setSubmitting(false);
      }
      return;
    }

    setSubmitting(true);
    try {
      await api.loginWithPassword(email.trim(), password);
      await onAuthenticated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-dvh w-full bg-slate-100 dark:bg-[#0f1218] text-slate-900 dark:text-slate-100 flex items-center justify-center p-6">
      <div className="w-full max-w-[420px] rounded-2xl border border-slate-300 dark:border-[#2a3342] bg-white dark:bg-[#161b24] p-7 shadow-xl space-y-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 flex items-center justify-center text-lg font-bold tracking-tight shrink-0">
            A
          </div>
          <div className="min-w-0">
            <h1 className="text-lg font-bold tracking-tight leading-tight">
              {mode === "bootstrap"
                ? "Initialize Argo Admin"
                : mode === "change_password"
                  ? "Update Your Password"
                  : "Sign in · Argo"}
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate">
              {mode === "bootstrap"
                ? "Create your first administrator credentials"
                : mode === "change_password"
                  ? principal?.email || "First-time password rotation required"
                  : authConfig?.auth_mode === "hybrid"
                    ? "Invite-only workspace · Email/Password or Google"
                    : "Workspace credentials sign-in"}
            </p>
          </div>
        </div>

        {error && (
          <div className="rounded-xl border border-rose-300 dark:border-rose-800/70 bg-rose-50 dark:bg-rose-950/40 px-3.5 py-2.5 text-xs text-rose-700 dark:text-rose-200 leading-relaxed">
            {error}
          </div>
        )}

        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-3.5">
          {mode !== "change_password" && (
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                Email
              </label>
              <input
                type="email"
                required
                autoFocus
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-2.5 text-sm outline-none focus:border-slate-900 dark:focus:border-slate-400"
              />
            </div>
          )}

          {mode === "bootstrap" && (
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                Display Name (optional)
              </label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Workspace Admin"
                className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-2.5 text-sm outline-none focus:border-slate-900 dark:focus:border-slate-400"
              />
            </div>
          )}

          {mode === "change_password" && (
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                Temporary / Current Password
              </label>
              <input
                type="password"
                required
                autoFocus
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter your temporary password"
                className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-2.5 text-sm outline-none focus:border-slate-900 dark:focus:border-slate-400"
              />
            </div>
          )}

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
              {mode === "change_password"
                ? "New Password (min 8 chars)"
                : mode === "bootstrap"
                  ? "Admin Password (min 8 chars)"
                  : "Password"}
            </label>
            <input
              type="password"
              required
              minLength={mode === "login" ? 1 : 8}
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-2.5 text-sm outline-none focus:border-slate-900 dark:focus:border-slate-400"
            />
          </div>

          {(mode === "bootstrap" || mode === "change_password") && (
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                Confirm Password
              </label>
              <input
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-3.5 py-2.5 text-sm outline-none focus:border-slate-900 dark:focus:border-slate-400"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full h-11 rounded-xl bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-slate-200 text-white dark:text-slate-900 font-semibold text-sm inline-flex items-center justify-center gap-2 disabled:opacity-60 cursor-pointer"
          >
            {submitting ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : mode === "bootstrap" ? (
              <ShieldCheck className="w-4 h-4" />
            ) : (
              <KeyRound className="w-4 h-4" />
            )}
            <span>
              {mode === "bootstrap"
                ? "Create Admin Account"
                : mode === "change_password"
                  ? "Save Password & Continue"
                  : "Sign in"}
            </span>
          </button>
        </form>

        {mode === "login" && googleEnabled && (
          <>
            <div className="relative flex items-center py-0.5">
              <div className="flex-1 border-t border-slate-200 dark:border-slate-700" />
              <span className="px-3 text-[11px] uppercase tracking-wider text-slate-400">or</span>
              <div className="flex-1 border-t border-slate-200 dark:border-slate-700" />
            </div>
            <button
              type="button"
              onClick={() => window.location.assign("/api/auth/google/start")}
              className="w-full h-11 rounded-xl border border-slate-300 dark:border-slate-700 bg-white hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-900 dark:text-slate-100 font-semibold text-sm inline-flex items-center justify-center gap-2.5 cursor-pointer"
            >
              <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" aria-hidden="true">
                <path
                  fill="#4285F4"
                  d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17Z"
                />
                <path
                  fill="#34A853"
                  d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.11-6.72-4.96H1.29v3.14C3.26 21.3 7.31 24 12 24Z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.28 14.24c-.24-.72-.38-1.49-.38-2.24s.14-1.52.38-2.24V6.62H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.38l3.99-3.14Z"
                />
                <path
                  fill="#EA4335"
                  d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.62l3.99 3.14c.95-2.85 3.6-4.96 6.72-4.96Z"
                />
              </svg>
              <span>Sign in with Google</span>
            </button>
          </>
        )}

        {mode === "change_password" && onLogout && (
          <button
            type="button"
            onClick={() => void onLogout()}
            className="w-full rounded-xl border border-slate-200 dark:border-slate-700 py-2 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 inline-flex items-center justify-center gap-1.5 cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign out</span>
          </button>
        )}
      </div>
    </div>
  );
}
