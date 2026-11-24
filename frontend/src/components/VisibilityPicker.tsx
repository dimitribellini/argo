import { Globe, Lock, Users } from "lucide-react";
import type { ResourceVisibility, TeamGroupRecord } from "../types";

export function formatVisibilityLabel(
  visibility?: ResourceVisibility | string,
  allowedGroups?: string[],
): string {
  if (visibility === "shared") return "Shared";
  if (visibility === "team") {
    const count = allowedGroups?.length ?? 0;
    return count > 0 ? `Team (${count})` : "Team";
  }
  return "Private";
}

export function visibilityBadgeClasses(visibility?: ResourceVisibility | string): string {
  if (visibility === "shared") {
    return "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/60";
  }
  if (visibility === "team") {
    return "bg-indigo-50 text-indigo-700 border-indigo-200 dark:bg-indigo-950/40 dark:text-indigo-300 dark:border-indigo-800/60";
  }
  return "bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800/60 dark:text-slate-300 dark:border-slate-700";
}

interface VisibilityPickerProps {
  value: ResourceVisibility;
  allowedGroups: string[];
  teams: TeamGroupRecord[];
  onChange: (visibility: ResourceVisibility, allowedGroups: string[]) => void;
  label?: string;
  compact?: boolean;
}

export function VisibilityPicker({
  value,
  allowedGroups,
  teams,
  onChange,
  label = "Visibility",
  compact = false,
}: VisibilityPickerProps) {
  const handleSelectVis = (next: ResourceVisibility) => {
    if (next !== "team") {
      onChange(next, []);
      return;
    }
    const fallback =
      allowedGroups.length > 0
        ? allowedGroups
        : teams[0]
          ? [teams[0].slug]
          : [];
    onChange("team", fallback);
  };

  const toggleGroup = (slug: string) => {
    const exists = allowedGroups.includes(slug);
    const next = exists
      ? allowedGroups.filter((g) => g !== slug)
      : [...allowedGroups, slug];
    onChange("team", next);
  };

  const options: Array<{
    key: ResourceVisibility;
    title: string;
    icon: typeof Lock;
    hint: string;
  }> = [
    { key: "private", title: "Private", icon: Lock, hint: "Only you & admins" },
    { key: "team", title: "Team", icon: Users, hint: "Selected groups" },
    { key: "shared", title: "Shared", icon: Globe, hint: "All workspace users" },
  ];

  return (
    <div className="space-y-1.5">
      {label && (
        <label className="block text-[11px] font-semibold text-slate-600 dark:text-slate-300">
          {label}
        </label>
      )}
      <div className="grid grid-cols-3 gap-1.5">
        {options.map((opt) => {
          const active = value === opt.key;
          const Icon = opt.icon;
          return (
            <button
              key={opt.key}
              type="button"
              onClick={() => handleSelectVis(opt.key)}
              className={`rounded-lg border px-2 py-1.5 text-left transition cursor-pointer ${
                active
                  ? "border-slate-900 bg-slate-900 text-white dark:border-slate-100 dark:bg-slate-100 dark:text-slate-900"
                  : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"
              }`}
            >
              <div className="flex items-center gap-1 text-[11px] font-semibold">
                <Icon className="w-3 h-3 shrink-0" />
                <span>{opt.title}</span>
              </div>
              {!compact && (
                <div className="text-[10px] opacity-75 truncate mt-0.5">{opt.hint}</div>
              )}
            </button>
          );
        })}
      </div>

      {value === "team" && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-900/50 p-2 space-y-1.5">
          {teams.length === 0 ? (
            <p className="text-[11px] text-amber-700 dark:text-amber-300">
              No Team Groups available yet. Ask an Admin to create a Team Group under{" "}
              <span className="font-semibold">Settings → Users &amp; Teams</span>.
            </p>
          ) : (
            <>
              <div className="text-[10px] font-medium text-slate-500 dark:text-slate-400">
                Allowed Team Groups {allowedGroups.length === 0 ? "(select at least 1)" : ""}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {teams.map((grp) => {
                  const selected = allowedGroups.includes(grp.slug);
                  return (
                    <button
                      key={grp.slug}
                      type="button"
                      onClick={() => toggleGroup(grp.slug)}
                      className={`px-2 py-0.5 rounded-full text-[11px] font-medium border transition cursor-pointer ${
                        selected
                          ? "bg-indigo-600 text-white border-indigo-600"
                          : "bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700 hover:border-indigo-400"
                      }`}
                    >
                      {grp.name}
                    </button>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
