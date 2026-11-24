import { ChevronRight, FileText, Plus, Settings } from "lucide-react";
import type { BotRecord, PageRecord, SettingsTab } from "../types";
import { BotAvatar } from "./BotAvatar";

interface MobilePagesHubProps {
  pages: PageRecord[];
  bots: BotRecord[];
  onSelectPage: (slug: string) => void;
  onOpenNewPage: () => void;
  onOpenSettings: (tab?: SettingsTab) => void;
}

export function MobilePagesHub({
  pages,
  bots,
  onSelectPage,
  onOpenNewPage,
  onOpenSettings,
}: MobilePagesHubProps) {
  const botBySlug = new Map(bots.map((b) => [b.slug, b]));

  return (
    <div className="flex flex-col h-full min-h-0 bg-slate-50">
      <header className="shrink-0 argo-safe-top bg-white border-b border-slate-200 px-4">
        <div className="h-14 flex items-center justify-between gap-3">
          <div>
            <h1 className="text-[15px] font-semibold text-slate-900 leading-tight">Pages</h1>
            <p className="text-[11px] text-slate-500 leading-tight">
              Interactive dashboards updated by your bots
            </p>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => onOpenSettings("integrations")}
              aria-label="Settings"
              className="w-9 h-9 rounded-full border border-slate-200 bg-white text-slate-700 flex items-center justify-center cursor-pointer"
            >
              <Settings className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={onOpenNewPage}
              aria-label="New Page"
              className="inline-flex items-center gap-1 px-3 h-9 rounded-full bg-slate-900 text-white text-xs font-semibold cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New</span>
            </button>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-y-auto custom-scroll px-4 py-4">
        {pages.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-6 text-center space-y-3">
            <div className="w-10 h-10 rounded-xl bg-slate-100 text-slate-500 flex items-center justify-center mx-auto">
              <FileText className="w-5 h-5" />
            </div>
            <div className="text-sm font-semibold text-slate-900">No Pages yet</div>
            <p className="text-xs text-slate-500">
              Ask any bot to build a dashboard, or create a Page directly.
            </p>
            <button
              type="button"
              onClick={onOpenNewPage}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-full bg-slate-900 text-white text-xs font-semibold cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Create Page</span>
            </button>
          </div>
        ) : (
          <div className="rounded-2xl border border-slate-200 bg-white divide-y divide-slate-100 overflow-hidden">
            {pages.map((page) => {
              const owner = botBySlug.get(page.owner_bot_slug);
              return (
                <button
                  key={page.id}
                  type="button"
                  onClick={() => onSelectPage(page.slug)}
                  className="w-full flex items-center gap-3 px-3.5 py-3.5 text-left active:bg-slate-100 transition cursor-pointer"
                >
                  {owner ? (
                    <BotAvatar
                      icon={owner.avatar_icon}
                      color={owner.avatar_color}
                      initials={owner.initials}
                      size="md"
                    />
                  ) : (
                    <div className="w-8 h-8 rounded-xl bg-slate-100 border border-slate-200 flex items-center justify-center shrink-0">
                      <FileText className="w-4 h-4 text-slate-600" />
                    </div>
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-slate-900 truncate">
                      {page.title}
                    </div>
                    <div className="text-xs text-slate-500 truncate mt-0.5">
                      {owner ? `Updated by ${owner.name}` : page.render_mode === "sandboxed_html" ? "Interactive HTML" : "Structured View"}
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 shrink-0" />
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
