"use client";

import Link from "next/link";
import { useState } from "react";
import { usePolled, useDecisionStream } from "@/lib/api";
import type { Decision, Metrics } from "@/lib/types";
import { REASON_HELP, REASON_LABEL, num } from "@/lib/format";
import { Badge, Empty, ErrorNote, Panel, Stat } from "@/components/ui";

type Filter = "all" | "verify" | "suppressed";

export default function DecisionsPage() {
  const [filter, setFilter] = useState<Filter>("all");
  const { decisions, connected } = useDecisionStream(400);

  // Filtering happens server-side. Narrowing the live buffer instead would only
  // ever surface events since this page connected, which for something as rare
  // as a verification means showing one row next to a counter reading 34.
  const query =
    filter === "verify"
      ? "/decisions?limit=200&action=verify"
      : filter === "suppressed"
        ? "/decisions?limit=200&reason=cooldown,budget_exhausted"
        : "/decisions?limit=200";
  const { data: recent, error } = usePolled<Decision[]>(query, 3000);
  const { data: metrics } = usePolled<Metrics>("/metrics", 3000);

  // On the unfiltered view prefer the live stream, which updates instantly.
  const filtered =
    filter === "all" && decisions.length ? decisions : (recent ?? []);

  const suppressed =
    (metrics?.reasons.cooldown ?? 0) + (metrics?.reasons.budget_exhausted ?? 0);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink-200">Decisions</h1>
          <p className="mt-0.5 max-w-3xl text-[11px] text-ink-400">
            Every step the engine took, and why. The reason matters more than
            the action: an agent left alone because it is trusted is a very
            different situation from one left alone because the budget ran out.
          </p>
        </div>
        <Badge tone={connected ? "good" : "neutral"}>
          {connected ? "streaming" : "polling"}
        </Badge>
      </div>

      {error && <ErrorNote message={error} />}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Steps" value={metrics?.steps.toLocaleString() ?? "—"} />
        <Stat
          label="Verifications"
          value={metrics?.verifications ?? "—"}
          hint={metrics ? `${num(metrics.budget_per_1k_steps)}/1k steps` : undefined}
        />
        <Stat
          label="Suppressed"
          value={suppressed}
          tone={suppressed > 0 ? "warn" : "default"}
          hint="wanted to verify, could not"
        />
        <Stat
          label="Adapter unknowns"
          value={
            metrics
              ? Object.values(metrics.adapter_unknowns).reduce((a, b) => a + b, 0)
              : "—"
          }
          hint="checks that could not be performed"
        />
      </div>

      {metrics && Object.keys(metrics.reasons).length > 0 && (
        <Panel
          title="Reason breakdown"
          subtitle="Where the policy is actually binding."
        >
          <div className="flex flex-wrap gap-4">
            {Object.entries(metrics.reasons)
              .sort((a, b) => b[1] - a[1])
              .map(([reason, count]) => (
                <div
                  key={reason}
                  title={REASON_HELP[reason]}
                  className="rounded border border-ink-700 bg-ink-850 px-3 py-1.5"
                >
                  <div className="text-[10px] uppercase tracking-wide text-ink-400">
                    {REASON_LABEL[reason] ?? reason}
                  </div>
                  <div className="tnum text-[15px] text-ink-200">
                    {count.toLocaleString()}
                  </div>
                </div>
              ))}
          </div>
        </Panel>
      )}

      <Panel
        title="Stream"
        right={
          <div className="flex gap-1">
            {(["all", "verify", "suppressed"] as Filter[]).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`rounded px-2 py-1 text-[11px] transition-colors ${
                  filter === f
                    ? "bg-ink-700 text-ink-200"
                    : "text-ink-400 hover:text-ink-200"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        }
      >
        {!filtered.length ? (
          <Empty>
            {filter === "all"
              ? "No decisions yet. Start the feed from the Fleet page."
              : "Nothing has matched this filter yet."}
          </Empty>
        ) : (
          <div className="max-h-[560px] overflow-y-auto">
            <table className="w-full text-left text-[12px]">
              <thead className="sticky top-0 bg-ink-900">
                <tr className="border-b border-ink-700 text-[10px] uppercase tracking-wider text-ink-400">
                  <th className="pb-2 pr-3 font-normal">At</th>
                  <th className="pb-2 pr-3 font-normal">Agent</th>
                  <th className="pb-2 pr-3 text-right font-normal">p</th>
                  <th className="pb-2 pr-3 text-right font-normal">Trust</th>
                  <th className="pb-2 pr-3 font-normal">Action</th>
                  <th className="pb-2 font-normal">Reason</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((d, i) => (
                  <tr
                    key={`${d.agent_id}-${d.timestamp}-${i}`}
                    className="border-b border-ink-850/70 last:border-0 hover:bg-ink-850/50"
                  >
                    <td className="py-1.5 pr-3 tnum text-ink-400">
                      {d.timestamp.toFixed(2)}
                    </td>
                    <td className="py-1.5 pr-3">
                      <Link
                        href={`/agents/${encodeURIComponent(d.agent_id)}`}
                        className="text-ink-300 hover:text-sky-400"
                      >
                        {d.agent_id}
                      </Link>
                    </td>
                    <td className="py-1.5 pr-3 text-right tnum text-ink-400">
                      {d.p.toFixed(3)}
                    </td>
                    <td
                      className={`py-1.5 pr-3 text-right tnum ${
                        d.trust < 0.5 ? "text-rose-400" : "text-ink-300"
                      }`}
                    >
                      {d.trust.toFixed(3)}
                    </td>
                    <td className="py-1.5 pr-3">
                      {d.action === "verify" ? (
                        <Badge tone="warn">verify</Badge>
                      ) : (
                        <span className="text-ink-500">observe</span>
                      )}
                    </td>
                    <td className="py-1.5 text-ink-400" title={REASON_HELP[d.reason]}>
                      {REASON_LABEL[d.reason] ?? d.reason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
