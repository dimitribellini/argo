import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Check,
  KeyRound,
  Pencil,
  Plus,
  RefreshCw,
  Shield,
  Trash2,
  UserPlus,
  Users,
  X,
} from "lucide-react";
import { api } from "../../api";
import type { AdminUserRecord, SsoPrincipal, TeamGroupRecord } from "../../types";

interface UsersTeamsViewProps {
  principal: SsoPrincipal | null;
  onChanged?: () => Promise<void>;
  onToast?: (msg: string) => void;
}

function generateTempPassword(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#";
  const arr = new Uint32Array(14);
  if (typeof window !== "undefined" && window.crypto?.getRandomValues) {
    window.crypto.getRandomValues(arr);
  }
  return Array.from(arr, (n) => chars[n % chars.length]).join("");
}

export function UsersTeamsView({ principal, onChanged, onToast }: UsersTeamsViewProps) {
  const [users, setUsers] = useState<AdminUserRecord[]>([]);
  const [teams, setTeams] = useState<TeamGroupRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New / Edit user form
  const [userFormOpen, setUserFormOpen] = useState(false);
  const [editingUserEmail, setEditingUserEmail] = useState<string | null>(null);
  const [uEmail, setUEmail] = useState("");
  const [uName, setUName] = useState("");
  const [uRole, setURole] = useState<"admin" | "member">("member");
  const [uAuthPw, setUAuthPw] = useState(true);
  const [uAuthGoogle, setUAuthGoogle] = useState(true);
  const [uPassword, setUPassword] = useState("");
  const [uMustChangePw, setUMustChangePw] = useState(true);
  const [uGroups, setUGroups] = useState<string[]>([]);
  const [uDeskQuota, setUDeskQuota] = useState("");
  const [uSbQuota, setUSbQuota] = useState("");
  const [savingUser, setSavingUser] = useState(false);

  // Inline password reset dialog
  const [resetEmail, setResetEmail] = useState<string | null>(null);
  const [resetPasswordVal, setResetPasswordVal] = useState("");
  const [resetMustChange, setResetMustChange] = useState(true);

  // Team Group form
  const [teamFormOpen, setTeamFormOpen] = useState(false);
  const [editingTeamSlug, setEditingTeamSlug] = useState<string | null>(null);
  const [tName, setTName] = useState("");
  const [tDesc, setTDesc] = useState("");
  const [tMembers, setTMembers] = useState<string[]>([]);
  const [savingTeam, setSavingTeam] = useState(false);

  const callerEmail = (principal?.email || "").toLowerCase();

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [uRes, tRes] = await Promise.all([api.listAdminUsers(), api.listMyTeams()]);
      setUsers(uRes);
      setTeams(tRes);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load users and team groups.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const openCreateUser = () => {
    setEditingUserEmail(null);
    setUEmail("");
    setUName("");
    setURole("member");
    setUAuthPw(true);
    setUAuthGoogle(true);
    setUPassword(generateTempPassword());
    setUMustChangePw(true);
    setUGroups([]);
    setUDeskQuota("");
    setUSbQuota("");
    setUserFormOpen(true);
  };

  const openEditUser = (u: AdminUserRecord) => {
    setEditingUserEmail(u.email);
    setUEmail(u.email);
    setUName(u.display_name || "");
    setURole(u.role === "admin" ? "admin" : "member");
    setUAuthPw(u.auth_methods.includes("password"));
    setUAuthGoogle(u.auth_methods.includes("google"));
    setUPassword("");
    setUMustChangePw(u.must_change_password);
    setUGroups(u.groups.map((g) => g.slug));
    setUDeskQuota(u.max_active_desktops != null ? String(u.max_active_desktops) : "");
    setUSbQuota(u.max_active_sandboxes != null ? String(u.max_active_sandboxes) : "");
    setUserFormOpen(true);
  };

  const handleSaveUser = async (e: FormEvent) => {
    e.preventDefault();
    const methods: Array<"password" | "google"> = [];
    if (uAuthPw) methods.push("password");
    if (uAuthGoogle) methods.push("google");
    if (methods.length === 0) {
      setError("Select at least one sign-in method (Password or Google).");
      return;
    }
    setSavingUser(true);
    setError(null);
    try {
      const deskNum = uDeskQuota.trim() !== "" ? Number(uDeskQuota) : undefined;
      const sbNum = uSbQuota.trim() !== "" ? Number(uSbQuota) : undefined;
      if (editingUserEmail) {
        await api.updateAdminUser(editingUserEmail, {
          display_name: uName.trim(),
          role: uRole,
          auth_methods: methods,
          group_slugs: uGroups,
          clear_quota_overrides: true,
          ...(deskNum !== undefined && !Number.isNaN(deskNum) ? { max_active_desktops: deskNum } : {}),
          ...(sbNum !== undefined && !Number.isNaN(sbNum) ? { max_active_sandboxes: sbNum } : {}),
        });
        onToast?.(`Updated user ${editingUserEmail}`);
      } else {
        await api.createAdminUser({
          email: uEmail.trim(),
          display_name: uName.trim(),
          role: uRole,
          auth_methods: methods,
          ...(uAuthPw && uPassword.trim() ? { password: uPassword, must_change_password: uMustChangePw } : {}),
          group_slugs: uGroups,
          ...(deskNum !== undefined && !Number.isNaN(deskNum) ? { max_active_desktops: deskNum } : {}),
          ...(sbNum !== undefined && !Number.isNaN(sbNum) ? { max_active_sandboxes: sbNum } : {}),
        });
        onToast?.(`Invited ${uEmail.trim()}`);
      }
      setUserFormOpen(false);
      await loadData();
      await onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save user.");
    } finally {
      setSavingUser(false);
    }
  };

  const handleToggleActive = async (u: AdminUserRecord) => {
    setError(null);
    try {
      await api.updateAdminUser(u.email, { active: !u.active });
      onToast?.(`${u.active ? "Disabled" : "Enabled"} ${u.email}`);
      await loadData();
      await onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update account status.");
    }
  };

  const handleDeleteUser = async (email: string) => {
    if (!window.confirm(`Delete invited user '${email}'? This will immediately terminate all sessions.`)) {
      return;
    }
    setError(null);
    try {
      await api.deleteAdminUser(email);
      onToast?.(`Deleted ${email}`);
      await loadData();
      await onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete user.");
    }
  };

  const handleResetPasswordSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!resetEmail) return;
    setError(null);
    try {
      await api.resetAdminUserPassword(resetEmail, resetPasswordVal, resetMustChange);
      onToast?.(`Password updated for ${resetEmail}`);
      setResetEmail(null);
      setResetPasswordVal("");
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reset password.");
    }
  };

  const openCreateTeam = () => {
    setEditingTeamSlug(null);
    setTName("");
    setTDesc("");
    setTMembers([]);
    setTeamFormOpen(true);
  };

  const openEditTeam = (grp: TeamGroupRecord) => {
    setEditingTeamSlug(grp.slug);
    setTName(grp.name);
    setTDesc(grp.description || "");
    setTMembers([...grp.member_emails]);
    setTeamFormOpen(true);
  };

  const handleSaveTeam = async (e: FormEvent) => {
    e.preventDefault();
    setSavingTeam(true);
    setError(null);
    try {
      if (editingTeamSlug) {
        await api.updateAdminTeam(editingTeamSlug, {
          name: tName.trim(),
          description: tDesc.trim(),
          member_emails: tMembers,
        });
        onToast?.(`Updated Team Group ${tName.trim()}`);
      } else {
        await api.createAdminTeam({
          name: tName.trim(),
          description: tDesc.trim(),
          member_emails: tMembers,
        });
        onToast?.(`Created Team Group ${tName.trim()}`);
      }
      setTeamFormOpen(false);
      await loadData();
      await onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save Team Group.");
    } finally {
      setSavingTeam(false);
    }
  };

  const handleDeleteTeam = async (grp: TeamGroupRecord) => {
    if (
      !window.confirm(
        `Delete Team Group '${grp.name}'? Resources shared only with this team will revert to Private.`,
      )
    ) {
      return;
    }
    setError(null);
    try {
      await api.deleteAdminTeam(grp.slug);
      onToast?.(`Deleted Team Group ${grp.name}`);
      await loadData();
      await onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete Team Group.");
    }
  };

  return (
    <div className="space-y-6">
      {!principal?.multi_user && (
        <div className="rounded-xl border border-amber-300 bg-amber-50 px-3.5 py-2.5 text-xs text-amber-900">
          Invited users and Team Groups are active for authentication and Admin RBAC. Set{" "}
          <code className="font-mono font-semibold">ARGO_MULTI_USER=true</code> in{" "}
          <code className="font-mono">compose.yml</code> to enforce{" "}
          <span className="font-semibold">Private | Team | Shared</span> resource isolation between users.
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-300 bg-rose-50 px-3.5 py-2.5 text-xs text-rose-700 flex items-center justify-between gap-2">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)} className="cursor-pointer">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Users Section */}
      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div>
            <h3 className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-slate-500" />
              <span>Invited Users ({users.length})</span>
            </h3>
            <p className="text-[11px] text-slate-500">
              Only active accounts listed here can sign in with Password or Google ({principal?.auth_mode ?? "sso"}).
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void loadData()}
              className="px-2.5 py-1.5 rounded-lg border border-slate-200 text-xs text-slate-600 hover:bg-slate-50 inline-flex items-center gap-1 cursor-pointer"
            >
              <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>
            <button
              type="button"
              onClick={openCreateUser}
              className="px-3 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 cursor-pointer"
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>Invite User</span>
            </button>
          </div>
        </div>

        {userFormOpen && (
          <form
            onSubmit={(e) => void handleSaveUser(e)}
            className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5 space-y-3"
          >
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold text-slate-800">
                {editingUserEmail ? `Edit User · ${editingUserEmail}` : "Invite New User"}
              </div>
              <button
                type="button"
                onClick={() => setUserFormOpen(false)}
                className="text-slate-400 hover:text-slate-700 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {!editingUserEmail && (
                <div>
                  <label className="block text-[11px] font-semibold text-slate-600 mb-1">Email</label>
                  <input
                    type="email"
                    required
                    value={uEmail}
                    onChange={(e) => setUEmail(e.target.value)}
                    placeholder="user@company.com"
                    className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                  />
                </div>
              )}
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">Display Name</label>
                <input
                  type="text"
                  value={uName}
                  onChange={(e) => setUName(e.target.value)}
                  placeholder="Jane Doe"
                  className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">Role</label>
                <select
                  value={uRole}
                  onChange={(e) => setURole(e.target.value === "admin" ? "admin" : "member")}
                  className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                >
                  <option value="member">Member (Own + Team + Shared resources)</option>
                  <option value="admin">Admin (Models, Users &amp; Global Management)</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                  Allowed Sign-In Methods
                </label>
                <div className="flex items-center gap-3 pt-1 text-xs">
                  <label className="inline-flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={uAuthPw}
                      onChange={(e) => setUAuthPw(e.target.checked)}
                    />
                    <span>Password</span>
                  </label>
                  <label className="inline-flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={uAuthGoogle}
                      onChange={(e) => setUAuthGoogle(e.target.checked)}
                    />
                    <span>Google Sign-In</span>
                  </label>
                </div>
              </div>
            </div>

            {!editingUserEmail && uAuthPw && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 items-end">
                <div>
                  <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                    Temporary Password {uAuthGoogle ? "(optional for Google users)" : "(required)"}
                  </label>
                  <div className="flex gap-1.5">
                    <input
                      type="text"
                      required={!uAuthGoogle}
                      minLength={uPassword ? 8 : undefined}
                      value={uPassword}
                      onChange={(e) => setUPassword(e.target.value)}
                      className="flex-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => setUPassword(generateTempPassword())}
                      className="px-2 py-1.5 rounded-lg border border-slate-200 bg-white text-[11px] font-medium hover:bg-slate-50 cursor-pointer"
                    >
                      Generate
                    </button>
                  </div>
                </div>
                <label className="inline-flex items-center gap-1.5 text-xs pb-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={uMustChangePw}
                    onChange={(e) => setUMustChangePw(e.target.checked)}
                  />
                  <span>Require password change on first login</span>
                </label>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                  Active Desktop Quota Override (blank = default)
                </label>
                <input
                  type="number"
                  min={0}
                  max={64}
                  value={uDeskQuota}
                  onChange={(e) => setUDeskQuota(e.target.value)}
                  placeholder={String(principal?.max_active_desktops_per_user ?? 2)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                  Active Sandbox Quota Override (blank = default)
                </label>
                <input
                  type="number"
                  min={0}
                  max={64}
                  value={uSbQuota}
                  onChange={(e) => setUSbQuota(e.target.value)}
                  placeholder={String(principal?.max_active_sandboxes_per_user ?? 4)}
                  className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                />
              </div>
            </div>

            {teams.length > 0 && (
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                  Team Group Memberships
                </label>
                <div className="flex flex-wrap gap-1.5">
                  {teams.map((grp) => {
                    const selected = uGroups.includes(grp.slug);
                    return (
                      <button
                        key={grp.slug}
                        type="button"
                        onClick={() =>
                          setUGroups((prev) =>
                            selected ? prev.filter((s) => s !== grp.slug) : [...prev, grp.slug],
                          )
                        }
                        className={`px-2 py-0.5 rounded-full text-[11px] font-medium border cursor-pointer ${
                          selected
                            ? "bg-indigo-600 text-white border-indigo-600"
                            : "bg-white text-slate-700 border-slate-200"
                        }`}
                      >
                        {grp.name}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setUserFormOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={savingUser}
                className="px-3.5 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-medium inline-flex items-center gap-1 cursor-pointer disabled:opacity-60"
              >
                <Check className="w-3.5 h-3.5" />
                <span>{editingUserEmail ? "Save Changes" : "Create User"}</span>
              </button>
            </div>
          </form>
        )}

        {resetEmail && (
          <form
            onSubmit={(e) => void handleResetPasswordSubmit(e)}
            className="rounded-xl border border-indigo-200 bg-indigo-50/60 p-3 flex flex-wrap items-end gap-2.5"
          >
            <div className="flex-1 min-w-[200px]">
              <label className="block text-[11px] font-semibold text-slate-700 mb-1">
                New Password for {resetEmail}
              </label>
              <div className="flex gap-1.5">
                <input
                  type="text"
                  required
                  minLength={8}
                  value={resetPasswordVal}
                  onChange={(e) => setResetPasswordVal(e.target.value)}
                  className="flex-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs font-mono"
                />
                <button
                  type="button"
                  onClick={() => setResetPasswordVal(generateTempPassword())}
                  className="px-2 py-1 rounded-lg border border-slate-200 bg-white text-[11px] cursor-pointer"
                >
                  Generate
                </button>
              </div>
            </div>
            <label className="inline-flex items-center gap-1.5 text-xs pb-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={resetMustChange}
                onChange={(e) => setResetMustChange(e.target.checked)}
              />
              <span>Force change on login</span>
            </label>
            <div className="flex gap-1.5">
              <button
                type="button"
                onClick={() => setResetEmail(null)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-medium cursor-pointer"
              >
                Reset
              </button>
            </div>
          </form>
        )}

        <div className="divide-y divide-slate-100">
          {users.map((u) => {
            const isSelf = u.email.toLowerCase() === callerEmail;
            return (
              <div
                key={u.email}
                className="py-2.5 flex items-center justify-between gap-3 flex-wrap text-xs"
              >
                <div className="min-w-0 space-y-0.5">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="font-semibold text-slate-900">
                      {u.display_name || u.email}
                    </span>
                    {u.display_name && (
                      <span className="text-[11px] text-slate-500">{u.email}</span>
                    )}
                    <span
                      className={`px-1.5 py-0.5 rounded-full text-[10px] font-medium border ${
                        u.role === "admin"
                          ? "bg-slate-900 text-white border-slate-900"
                          : "bg-slate-100 text-slate-700 border-slate-200"
                      }`}
                    >
                      {u.role === "admin" ? "Admin" : "Member"}
                    </span>
                    {!u.active && (
                      <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium border border-rose-200 bg-rose-50 text-rose-700">
                        Disabled
                      </span>
                    )}
                    {u.must_change_password && (
                      <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium border border-amber-200 bg-amber-50 text-amber-800">
                        Temp Password
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-500 flex items-center gap-2 flex-wrap">
                    <span>Auth: {u.auth_methods.join(" + ") || "none"}</span>
                    <span>
                      Teams:{" "}
                      {u.groups.length > 0 ? u.groups.map((g) => g.name).join(", ") : "None"}
                    </span>
                    {(u.max_active_desktops != null || u.max_active_sandboxes != null) && (
                      <span>
                        Quota: {u.max_active_desktops ?? "default"}D /{" "}
                        {u.max_active_sandboxes ?? "default"}S
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => openEditUser(u)}
                    className="px-2 py-1 rounded-lg border border-slate-200 hover:bg-slate-50 text-[11px] inline-flex items-center gap-1 cursor-pointer"
                  >
                    <Pencil className="w-3 h-3" />
                    <span>Edit</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setResetEmail(u.email);
                      setResetPasswordVal(generateTempPassword());
                      setResetMustChange(true);
                    }}
                    className="px-2 py-1 rounded-lg border border-slate-200 hover:bg-slate-50 text-[11px] inline-flex items-center gap-1 cursor-pointer"
                  >
                    <KeyRound className="w-3 h-3" />
                    <span>Password</span>
                  </button>
                  {!isSelf && (
                    <>
                      <button
                        type="button"
                        onClick={() => void handleToggleActive(u)}
                        className="px-2 py-1 rounded-lg border border-slate-200 hover:bg-slate-50 text-[11px] cursor-pointer"
                      >
                        {u.active ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleDeleteUser(u.email)}
                        title="Delete user"
                        className="p-1.5 rounded-lg border border-slate-200 text-slate-400 hover:text-rose-600 hover:border-rose-200 cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
          {!loading && users.length === 0 && (
            <div className="py-4 text-center text-xs text-slate-400">
              No invited user records yet. Click &ldquo;Invite User&rdquo; to pre-create accounts.
            </div>
          )}
        </div>
      </div>

      {/* Team Groups Section */}
      <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div>
            <h3 className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
              <Users className="w-3.5 h-3.5 text-slate-500" />
              <span>Team Groups ({teams.length})</span>
            </h3>
            <p className="text-[11px] text-slate-500">
              Share bots, rooms, pages, integrations, and Vault secrets exclusively with selected teams.
            </p>
          </div>
          <button
            type="button"
            onClick={openCreateTeam}
            className="px-3 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Team Group</span>
          </button>
        </div>

        {teamFormOpen && (
          <form
            onSubmit={(e) => void handleSaveTeam(e)}
            className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5 space-y-3"
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">Group Name</label>
                <input
                  type="text"
                  required
                  value={tName}
                  onChange={(e) => setTName(e.target.value)}
                  placeholder="Operations"
                  className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">Description</label>
                <input
                  type="text"
                  value={tDesc}
                  onChange={(e) => setTDesc(e.target.value)}
                  placeholder="Infra and SRE operators"
                  className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                />
              </div>
            </div>

            {users.length > 0 && (
              <div>
                <label className="block text-[11px] font-semibold text-slate-600 mb-1">Members</label>
                <div className="flex flex-wrap gap-1.5">
                  {users.map((u) => {
                    const selected = tMembers.includes(u.email);
                    return (
                      <button
                        key={u.email}
                        type="button"
                        onClick={() =>
                          setTMembers((prev) =>
                            selected ? prev.filter((m) => m !== u.email) : [...prev, u.email],
                          )
                        }
                        className={`px-2 py-0.5 rounded-full text-[11px] font-medium border cursor-pointer ${
                          selected
                            ? "bg-indigo-600 text-white border-indigo-600"
                            : "bg-white text-slate-700 border-slate-200"
                        }`}
                      >
                        {u.display_name || u.email}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setTeamFormOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-xs cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={savingTeam}
                className="px-3.5 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-medium inline-flex items-center gap-1 cursor-pointer disabled:opacity-60"
              >
                <Check className="w-3.5 h-3.5" />
                <span>{editingTeamSlug ? "Save Team" : "Create Team"}</span>
              </button>
            </div>
          </form>
        )}

        <div className="divide-y divide-slate-100">
          {teams.map((grp) => (
            <div
              key={grp.slug}
              className="py-2.5 flex items-center justify-between gap-3 flex-wrap text-xs"
            >
              <div className="min-w-0 space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-900">{grp.name}</span>
                  <span className="text-[10px] font-mono text-slate-400">@{grp.slug}</span>
                  <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium border border-indigo-200 bg-indigo-50 text-indigo-700">
                    {grp.member_emails.length} member{grp.member_emails.length === 1 ? "" : "s"}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500">
                  {grp.description ? `${grp.description} · ` : ""}
                  {grp.member_emails.join(", ") || "No members assigned"}
                </div>
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => openEditTeam(grp)}
                  className="px-2 py-1 rounded-lg border border-slate-200 hover:bg-slate-50 text-[11px] inline-flex items-center gap-1 cursor-pointer"
                >
                  <Pencil className="w-3 h-3" />
                  <span>Edit</span>
                </button>
                <button
                  type="button"
                  onClick={() => void handleDeleteTeam(grp)}
                  title="Delete team group"
                  className="p-1.5 rounded-lg border border-slate-200 text-slate-400 hover:text-rose-600 hover:border-rose-200 cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
          {!loading && teams.length === 0 && (
            <div className="py-4 text-center text-xs text-slate-400">
              No Team Groups created yet. Click &ldquo;New Team Group&rdquo; to organize access.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
