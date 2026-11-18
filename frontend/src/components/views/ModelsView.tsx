import type { ModelProvider, ModelsResponse } from "../../types";
import { formatFriendlyTime, friendlyModelName } from "../../utils/format";

interface ModelsViewProps {
  modelsData: ModelsResponse | null;
  onOpenNewModel: (initial?: ModelProvider) => void;
  onSetDefaultModel: (slug: string) => void;
  onTestModel: (slug: string) => void;
  onDeleteModel: (slug: string) => void;
  onPauseBot?: (botSlug: string) => Promise<void>;
  onSwitchBotToFlash?: (botSlug: string) => Promise<void>;
}

function statusPillTone(status: string): string {
  if (status === "success") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
  if (status === "blocked" || status === "escalated") {
    return "border-amber-200 bg-amber-50 text-amber-800";
  }
  return "border-rose-200 bg-rose-50 text-rose-700";
}

export function ModelsView({
  modelsData,
  onOpenNewModel,
  onSetDefaultModel,
  onTestModel,
  onDeleteModel,
  onPauseBot,
  onSwitchBotToFlash,
}: ModelsViewProps) {
  const providers = modelsData?.providers ?? [];
  const todayTokens = modelsData?.today_tokens ?? 0;
  const todayCost = modelsData?.today_cost_usd ?? 0;
  const monthTokens = modelsData?.month_tokens ?? 0;
  const monthCost = modelsData?.month_cost_usd ?? 0;
  const recentRuns = modelsData?.recent_runs ?? [];
  const usageByBot = modelsData?.usage_by_bot ?? [];
  const dedupToday = modelsData?.deduplicated_runs_today ?? 0;
  const dedupMonth = modelsData?.deduplicated_runs_month ?? 0;
  const maxBotTokens = Math.max(1, ...usageByBot.map((b) => b.month_tokens));

  return (
    <div className="h-full overflow-y-auto custom-scroll p-5">
      <div className="max-w-4xl mx-auto space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h2 className="text-xs font-semibold text-slate-900">
              AI Providers &amp; Spending Caps
            </h2>
            <p className="text-[11px] text-slate-500">
              Add API keys for Gemini, Grok, Claude, OpenAI, or local Ollama models with automatic failover
            </p>
          </div>
          <button
            type="button"
            onClick={() => onOpenNewModel()}
            className="bg-slate-900 text-white px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-800"
          >
            + Add AI Model
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {providers.map((provider) => (
            <div
              key={provider.id}
              className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-2.5"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-900 truncate">
                  {friendlyModelName(provider.model_id)}
                </span>
                <div className="flex items-center gap-1.5 shrink-0">
                  {provider.is_default && (
                    <span className="px-2 py-0.5 rounded-full border border-slate-300 bg-slate-100 text-slate-800 text-[11px] font-medium">
                      Default
                    </span>
                  )}
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-slate-600 text-[11px]">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        provider.has_api_key || provider.provider_type === "ollama"
                          ? "bg-[#3b8c62]"
                          : "bg-slate-400"
                      }`}
                    />
                    <span>
                      {provider.has_api_key
                        ? "Connected"
                        : provider.provider_type === "ollama"
                          ? "Local"
                          : "Needs Key"}
                    </span>
                  </span>
                </div>
              </div>

              <div className="text-[11px] text-slate-500 space-y-0.5">
                <div>
                  Provider: <span className="font-medium text-slate-700 capitalize">{provider.provider_type}</span>
                </div>
                {provider.api_base && (
                  <div className="text-[10px] text-slate-500 truncate">
                    Endpoint: {provider.api_base}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-500 border-t border-slate-100 pt-2">
                <div>
                  Daily Limit:{" "}
                  <span className="text-slate-700 font-medium">
                    {provider.daily_token_limit != null
                      ? `${(provider.today_tokens ?? 0).toLocaleString()} / ${provider.daily_token_limit.toLocaleString()}`
                      : "Unlimited"}
                  </span>
                </div>
                <div>
                  Monthly Spend:{" "}
                  <span className="text-slate-700 font-medium">
                    ${(provider.month_cost_usd ?? 0).toFixed(4)}
                    {provider.monthly_budget_usd != null
                      ? ` / $${provider.monthly_budget_usd.toFixed(2)}`
                      : ""}
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between pt-1 text-[11px] gap-2">
                <div className="flex items-center gap-2">
                  {!provider.is_default && (
                    <button
                      type="button"
                      onClick={() => onSetDefaultModel(provider.slug)}
                      className="px-2 py-1 rounded-lg border border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100 cursor-pointer"
                    >
                      Make Default
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => onTestModel(provider.slug)}
                    className="px-2 py-1 rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 cursor-pointer"
                  >
                    Test
                  </button>
                  <button
                    type="button"
                    onClick={() => onOpenNewModel(provider)}
                    className="px-2 py-1 rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 cursor-pointer"
                  >
                    Edit
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => onDeleteModel(provider.slug)}
                  className="text-rose-600 hover:underline cursor-pointer"
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs flex items-center justify-between gap-2">
            <div>
              <h3 className="text-xs font-semibold text-slate-900">Today&apos;s Usage</h3>
              <p className="text-[11px] text-slate-500">Tokens &amp; estimated cost</p>
            </div>
            <div className="text-right text-xs text-slate-900">
              <div className="font-semibold">{todayTokens.toLocaleString()} tokens</div>
              <div className="text-[11px] text-slate-500">${todayCost.toFixed(4)}</div>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs flex items-center justify-between gap-2">
            <div>
              <h3 className="text-xs font-semibold text-slate-900">This Month</h3>
              <p className="text-[11px] text-slate-500">Cumulative spend across bots</p>
            </div>
            <div className="text-right text-xs text-slate-900">
              <div className="font-semibold">{monthTokens.toLocaleString()} tokens</div>
              <div className="text-[11px] text-slate-500">${monthCost.toFixed(4)}</div>
            </div>
          </div>

          <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 shadow-xs flex items-center justify-between gap-2">
            <div>
              <h3 className="text-xs font-semibold text-emerald-900">0-Token Smart Checks</h3>
              <p className="text-[11px] text-emerald-700">Unchanged polls skipped</p>
            </div>
            <div className="text-right text-xs text-emerald-900">
              <div className="font-semibold">{dedupToday.toLocaleString()} today</div>
              <div className="text-[11px] text-emerald-700">{dedupMonth.toLocaleString()} this month</div>
            </div>
          </div>
        </div>

        {/* Find Usage Hogs */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
          <div>
            <h3 className="text-xs font-semibold text-slate-900">
              Usage by Bot &amp; Routine
            </h3>
            <p className="text-[11px] text-slate-500">
              Spot which automations consume the most tokens and throttle or downgrade them in one click
            </p>
          </div>
          {usageByBot.length === 0 ? (
            <div className="text-xs text-slate-400">No bot runs recorded this month yet.</div>
          ) : (
            <div className="space-y-2.5">
              {usageByBot.map((item) => {
                const pct = Math.max(4, Math.round((item.month_tokens / maxBotTokens) * 100));
                return (
                  <div
                    key={item.bot_slug}
                    className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div>
                        <span className="font-semibold text-slate-900">{item.bot_name}</span>
                        <span className="ml-2 text-[11px] text-slate-500">
                          {item.runs_count} runs · Top trigger: {item.top_trigger_type}
                        </span>
                      </div>
                      <div className="text-[11px] font-medium text-slate-800">
                        {item.month_tokens.toLocaleString()} tokens · ${item.month_cost_usd.toFixed(4)}
                      </div>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-200 overflow-hidden">
                      <div className="h-full bg-slate-900 rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                    {(onPauseBot || onSwitchBotToFlash) && (
                      <div className="flex items-center gap-2 justify-end">
                        {onSwitchBotToFlash && item.model && item.model !== "google:gemini-3.8-flash" && (
                          <button
                            type="button"
                            onClick={() => void onSwitchBotToFlash(item.bot_slug)}
                            className="px-2 py-1 rounded-lg border border-slate-200 bg-white text-[11px] text-slate-700 hover:bg-slate-100 cursor-pointer"
                          >
                            Switch to Gemini 3.8 Flash
                          </button>
                        )}
                        {onPauseBot && item.enabled && (
                          <button
                            type="button"
                            onClick={() => void onPauseBot(item.bot_slug)}
                            className="px-2 py-1 rounded-lg border border-amber-200 bg-amber-50 text-[11px] text-amber-800 hover:bg-amber-100 cursor-pointer"
                          >
                            Pause Bot
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-xs">
          <div className="px-4 py-3 border-b border-slate-200">
            <h3 className="text-xs font-semibold text-slate-900">Recent AI Runs</h3>
          </div>
          {recentRuns.length === 0 ? (
            <div className="p-4 text-xs text-slate-500 text-center">
              No runs recorded yet.
            </div>
          ) : (
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] text-slate-500 uppercase">
                  <th className="py-2 px-4">Bot</th>
                  <th className="py-2 px-4">Model</th>
                  <th className="py-2 px-4">Tokens</th>
                  <th className="py-2 px-4">Cost</th>
                  <th className="py-2 px-4">When</th>
                  <th className="py-2 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {recentRuns.map((run) => (
                  <tr key={run.id}>
                    <td className="py-2 px-4 font-medium text-slate-900">{run.bot_slug}</td>
                    <td className="py-2 px-4 text-[11px] text-slate-600">
                      {friendlyModelName(run.llm_model_used)}
                    </td>
                    <td className="py-2 px-4 text-[11px]">
                      {(run.input_tokens + run.output_tokens).toLocaleString()}
                    </td>
                    <td className="py-2 px-4 text-[11px]">${run.estimated_cost_usd.toFixed(4)}</td>
                    <td className="py-2 px-4 text-[11px] text-slate-400">
                      {formatFriendlyTime(run.started_at)}
                    </td>
                    <td className="py-2 px-4">
                      <span
                        className={`px-2 py-0.5 rounded-full border text-[10px] font-medium ${statusPillTone(
                          run.status,
                        )}`}
                      >
                        {run.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
