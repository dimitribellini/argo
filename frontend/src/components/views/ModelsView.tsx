import { useEffect, useMemo, useState } from "react";
import { api } from "../../api";
import type { BotRunRecord, ModelProvider, ModelsResponse, SsoPrincipal } from "../../types";
import { formatFriendlyTime, friendlyModelName } from "../../utils/format";

interface ModelsViewProps {
  principal?: SsoPrincipal | null;
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

function formatPricingBadge(provider: ModelProvider): string {
  const inRate = provider.effective_input_price_per_million;
  const outRate = provider.effective_output_price_per_million;
  if (provider.pricing_source === "local" || (inRate === 0 && outRate === 0)) {
    return "Local ($0.00 / 1M)";
  }
  if (inRate == null || outRate == null) {
    return "Est.";
  }
  const tag =
    provider.pricing_source === "custom"
      ? "Custom"
      : provider.pricing_source === "live"
        ? "Live"
        : "Est.";
  return `$${inRate.toFixed(2)} / $${outRate.toFixed(2)} per 1M · ${tag}`;
}

export function ModelsView({
  principal = null,
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

  const [selectedModelId, setSelectedModelId] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"cost" | "tokens">("cost");
  const [filteredRuns, setFilteredRuns] = useState<BotRunRecord[] | null>(null);
  const [loadingFilteredRuns, setLoadingFilteredRuns] = useState(false);

  useEffect(() => {
    if (!selectedModelId) {
      setFilteredRuns(null);
      setLoadingFilteredRuns(false);
      return;
    }
    let cancelled = false;
    setLoadingFilteredRuns(true);
    void api
      .listModels(selectedModelId)
      .then((res) => {
        if (!cancelled) {
          setFilteredRuns(res.recent_runs ?? []);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFilteredRuns(recentRuns.filter((r) => r.llm_model_used === selectedModelId));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoadingFilteredRuns(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedModelId, modelsData]);

  const filterableModels = useMemo(() => {
    const ids = new Set<string>();
    for (const p of providers) {
      if (p.model_id) ids.add(p.model_id);
    }
    for (const bot of usageByBot) {
      for (const slice of bot.models_used ?? []) {
        if (slice.model_id && slice.model_id !== "unknown") {
          ids.add(slice.model_id);
        }
      }
    }
    return Array.from(ids);
  }, [providers, usageByBot]);

  const displayedUsageByBot = useMemo(() => {
    const rows = usageByBot
      .map((item) => {
        const slices = item.models_used ?? [];
        if (!selectedModelId) {
          return {
            item,
            runs: item.runs_count,
            tokens: item.month_tokens,
            cost: item.month_cost_usd,
            slices,
          };
        }
        const match = slices.find((s) => s.model_id === selectedModelId);
        if (!match) return null;
        return {
          item,
          runs: match.runs_count,
          tokens: match.month_tokens,
          cost: match.month_cost_usd,
          slices: [match],
        };
      })
      .filter((entry): entry is NonNullable<typeof entry> => entry !== null);

    rows.sort((a, b) => {
      if (sortBy === "cost") {
        if (b.cost !== a.cost) return b.cost - a.cost;
        return b.tokens - a.tokens;
      }
      if (b.tokens !== a.tokens) return b.tokens - a.tokens;
      return b.cost - a.cost;
    });
    return rows;
  }, [usageByBot, selectedModelId, sortBy]);

  const maxMetricValue = Math.max(
    sortBy === "cost" ? 0.0001 : 1,
    ...displayedUsageByBot.map((r) => (sortBy === "cost" ? r.cost : r.tokens)),
  );

  const displayedRuns = selectedModelId ? (filteredRuns ?? []) : recentRuns;

  return (
    <div className="h-full overflow-y-auto custom-scroll p-5">
      <div className="max-w-4xl mx-auto space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h2 className="text-xs font-semibold text-slate-900">
              AI Providers &amp; Spending Caps
            </h2>
            <p className="text-[11px] text-slate-500">
              Add API keys for Gemini, Grok, Claude, OpenAI, OpenRouter, or local Ollama. Click a card to filter usage by model.
            </p>
          </div>
          {(!principal?.multi_user || principal?.is_admin) ? (
            <button
              type="button"
              onClick={() => onOpenNewModel()}
              className="bg-slate-900 text-white px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-800"
            >
              + Add AI Model
            </button>
          ) : (
            <span className="px-2.5 py-1 rounded-full border border-slate-200 bg-slate-50 text-[11px] text-slate-600">
              Workspace admins manage shared LLM providers and global budgets
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {providers.map((provider) => {
            const isSelected = selectedModelId === provider.model_id;
            return (
              <div
                key={provider.id}
                role="button"
                tabIndex={0}
                onClick={() =>
                  setSelectedModelId((prev) =>
                    prev === provider.model_id ? null : provider.model_id,
                  )
                }
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setSelectedModelId((prev) =>
                      prev === provider.model_id ? null : provider.model_id,
                    );
                  }
                }}
                className={`rounded-2xl border bg-white p-4 shadow-xs space-y-2.5 cursor-pointer transition-colors ${
                  isSelected
                    ? "border-slate-900 ring-1 ring-slate-900"
                    : "border-slate-200 hover:border-slate-300"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-900 truncate">
                    {friendlyModelName(provider.model_id)}
                  </span>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {isSelected && (
                      <span className="px-2 py-0.5 rounded-full border border-slate-900 bg-slate-900 text-white text-[10px] font-medium">
                        Filtered
                      </span>
                    )}
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
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span>
                      Provider:{" "}
                      <span className="font-medium text-slate-700 capitalize">
                        {provider.provider_type}
                      </span>
                    </span>
                    <span className="text-[10.5px] font-mono text-slate-500">
                      {formatPricingBadge(provider)}
                    </span>
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

                {(!principal?.multi_user || principal?.is_admin) && (
                  <div
                    className="flex items-center justify-between pt-1 text-[11px] gap-2"
                    onClick={(e) => e.stopPropagation()}
                  >
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
                )}
              </div>
            );
          })}
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

        {/* Usage by Bot & Model Attribution */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <div>
              <h3 className="text-xs font-semibold text-slate-900">
                Usage by Bot &amp; Routine
              </h3>
              <p className="text-[11px] text-slate-500">
                {selectedModelId
                  ? `Showing monthly spend on ${friendlyModelName(selectedModelId)} by bot`
                  : "Spot which automations consume the most budget or tokens and which models they used"}
              </p>
            </div>
            <div className="flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 p-0.5 text-[11px]">
              <button
                type="button"
                onClick={() => setSortBy("cost")}
                className={`px-2 py-1 rounded-md cursor-pointer font-medium ${
                  sortBy === "cost"
                    ? "bg-slate-900 text-white"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                By Cost
              </button>
              <button
                type="button"
                onClick={() => setSortBy("tokens")}
                className={`px-2 py-1 rounded-md cursor-pointer font-medium ${
                  sortBy === "tokens"
                    ? "bg-slate-900 text-white"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                By Tokens
              </button>
            </div>
          </div>

          {filterableModels.length > 1 && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={() => setSelectedModelId(null)}
                className={`px-2.5 py-1 rounded-full border text-[11px] font-medium cursor-pointer ${
                  selectedModelId === null
                    ? "border-slate-900 bg-slate-900 text-white"
                    : "border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100"
                }`}
              >
                All Models
              </button>
              {filterableModels.map((mid) => {
                const active = selectedModelId === mid;
                return (
                  <button
                    key={mid}
                    type="button"
                    onClick={() => setSelectedModelId((prev) => (prev === mid ? null : mid))}
                    className={`px-2.5 py-1 rounded-full border text-[11px] font-medium cursor-pointer ${
                      active
                        ? "border-slate-900 bg-slate-900 text-white"
                        : "border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100"
                    }`}
                  >
                    {friendlyModelName(mid)}
                  </button>
                );
              })}
            </div>
          )}

          {displayedUsageByBot.length === 0 ? (
            <div className="text-xs text-slate-400">
              {selectedModelId
                ? `No bot runs recorded on ${friendlyModelName(selectedModelId)} this month.`
                : "No bot runs recorded this month yet."}
            </div>
          ) : (
            <div className="space-y-2.5">
              {displayedUsageByBot.map(({ item, runs, tokens, cost, slices }) => {
                const metricVal = sortBy === "cost" ? cost : tokens;
                const pct = Math.max(4, Math.round((metricVal / maxMetricValue) * 100));
                return (
                  <div
                    key={item.bot_slug}
                    className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-900">{item.bot_name}</span>
                        {item.exists === false && (
                          <span className="px-1.5 py-0.5 rounded border border-slate-300 bg-white text-[10px] font-medium text-slate-500">
                            Deleted / System
                          </span>
                        )}
                        <span className="text-[11px] text-slate-500">
                          {runs} runs · Top trigger: {item.top_trigger_type}
                        </span>
                      </div>
                      <div className="text-[11px] font-medium text-slate-800">
                        {tokens.toLocaleString()} tokens · ${cost.toFixed(4)}
                      </div>
                    </div>

                    <div className="h-1.5 rounded-full bg-slate-200 overflow-hidden">
                      <div className="h-full bg-slate-900 rounded-full" style={{ width: `${pct}%` }} />
                    </div>

                    {slices.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {slices.map((sl) => (
                          <button
                            key={sl.model_id}
                            type="button"
                            onClick={() =>
                              setSelectedModelId((prev) =>
                                prev === sl.model_id ? null : sl.model_id,
                              )
                            }
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10.5px] cursor-pointer ${
                              selectedModelId === sl.model_id
                                ? "border-slate-900 bg-slate-900 text-white"
                                : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
                            }`}
                          >
                            <span className="font-medium">{friendlyModelName(sl.model_id)}</span>
                            <span>·</span>
                            <span>{sl.runs_count} runs</span>
                            <span>·</span>
                            <span>{sl.month_tokens.toLocaleString()} tok</span>
                            <span>·</span>
                            <span className="font-semibold">${sl.month_cost_usd.toFixed(4)}</span>
                          </button>
                        ))}
                      </div>
                    )}

                    {(onPauseBot || onSwitchBotToFlash) && item.exists !== false && (
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

        {Boolean(principal?.multi_user) && (modelsData?.usage_by_user?.length ?? 0) > 0 && (
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div>
                <h3 className="text-xs font-semibold text-slate-900">Usage by User</h3>
                <p className="text-[11px] text-slate-500">
                  Attributed runs, token consumption, and spend by operator email
                </p>
              </div>
              <span className="text-[11px] text-slate-500">
                {modelsData!.usage_by_user!.length} user(s)
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-[11px] text-slate-500 uppercase">
                    <th className="py-2 px-3">User</th>
                    <th className="py-2 px-3">Runs</th>
                    <th className="py-2 px-3">Today Tokens</th>
                    <th className="py-2 px-3">Month Tokens</th>
                    <th className="py-2 px-3">Month Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {modelsData!.usage_by_user!.map((u) => (
                    <tr key={u.email || "unknown"}>
                      <td className="py-2 px-3 font-medium text-slate-900">
                        {u.email || "system"}
                      </td>
                      <td className="py-2 px-3 text-[11px] text-slate-600">{u.runs_count}</td>
                      <td className="py-2 px-3 text-[11px]">
                        {u.today_tokens.toLocaleString()}
                      </td>
                      <td className="py-2 px-3 text-[11px]">
                        {u.month_tokens.toLocaleString()}
                      </td>
                      <td className="py-2 px-3 text-[11px] font-medium">
                        ${u.month_cost_usd.toFixed(4)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-xs">
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-semibold text-slate-900">Recent AI Runs</h3>
              {selectedModelId && (
                <span className="px-2 py-0.5 rounded-full border border-slate-300 bg-slate-100 text-[10.5px] font-medium text-slate-700">
                  {friendlyModelName(selectedModelId)}
                </span>
              )}
            </div>
            {selectedModelId && (
              <button
                type="button"
                onClick={() => setSelectedModelId(null)}
                className="text-[11px] text-slate-600 hover:text-slate-900 underline cursor-pointer"
              >
                Show all models
              </button>
            )}
          </div>
          {loadingFilteredRuns ? (
            <div className="p-4 text-xs text-slate-500 text-center">
              Loading runs for {selectedModelId ? friendlyModelName(selectedModelId) : "all models"}...
            </div>
          ) : displayedRuns.length === 0 ? (
            <div className="p-4 text-xs text-slate-500 text-center">
              No runs recorded yet.
            </div>
          ) : (
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-[11px] text-slate-500 uppercase">
                  <th className="py-2 px-4">Bot</th>
                  {Boolean(principal?.multi_user) && <th className="py-2 px-4">User</th>}
                  <th className="py-2 px-4">Model</th>
                  <th className="py-2 px-4">Tokens</th>
                  <th className="py-2 px-4">Cost</th>
                  <th className="py-2 px-4">When</th>
                  <th className="py-2 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {displayedRuns.map((run) => (
                  <tr key={run.id}>
                    <td className="py-2 px-4 font-medium text-slate-900">{run.bot_slug}</td>
                    {Boolean(principal?.multi_user) && (
                      <td className="py-2 px-4 text-[11px] text-slate-500">
                        {run.triggered_by_email || "—"}
                      </td>
                    )}
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
