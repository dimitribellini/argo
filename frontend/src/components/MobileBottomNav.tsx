import { Activity, Bot, CheckSquare, FileText } from "lucide-react";
import type { ViewId } from "../types";

interface MobileBottomNavProps {
  activeView: ViewId;
  pendingApprovals: number;
  onSelectTab: (tab: "bot" | "approvals" | "page" | "activity") => void;
}

export function MobileBottomNav({
  activeView,
  pendingApprovals,
  onSelectTab,
}: MobileBottomNavProps) {
  const tabs: Array<{
    id: "bot" | "approvals" | "page" | "activity";
    label: string;
    Icon: typeof Bot;
    badge?: number;
  }> = [
    { id: "bot", label: "Bots", Icon: Bot },
    { id: "approvals", label: "Approvals", Icon: CheckSquare, badge: pendingApprovals },
    { id: "page", label: "Pages", Icon: FileText },
    { id: "activity", label: "Activity", Icon: Activity },
  ];

  return (
    <nav
      aria-label="Primary navigation"
      className="shrink-0 bg-white border-t border-slate-200 argo-safe-bottom"
    >
      <div className="grid grid-cols-4 h-14">
        {tabs.map(({ id, label, Icon, badge }) => {
          const isActive = activeView === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => onSelectTab(id)}
              aria-current={isActive ? "page" : undefined}
              className={`relative flex flex-col items-center justify-center gap-0.5 text-[11px] font-medium transition cursor-pointer ${
                isActive ? "text-slate-900 font-semibold" : "text-slate-500"
              }`}
            >
              <span className="relative inline-flex items-center justify-center">
                <Icon className={`w-5 h-5 ${isActive ? "stroke-[2.25]" : "stroke-[1.75]"}`} />
                {typeof badge === "number" && badge > 0 && (
                  <span className="absolute -top-1.5 -right-2.5 min-w-[16px] h-4 px-1 rounded-full bg-amber-500 text-white text-[10px] font-bold flex items-center justify-center leading-none">
                    {badge > 99 ? "99+" : badge}
                  </span>
                )}
              </span>
              <span className="leading-none">{label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
