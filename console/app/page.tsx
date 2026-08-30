"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { api, usePolled, useDecisionStream } from "@/lib/api";
import type { Agent, Config, Feed, Metrics, TrajectoryPoint } from "@/lib/types";
import { duration, num } from "@/lib/format";
import { Sparkline } from "@/components/charts";
import { FeedControls } from "@/components/feed-controls";
import { Badge, Empty, ErrorNote, Panel, Stat, TrustBar } from "@/components/ui";

export default function FleetPage() {
  const { data: agents, error, refresh } = usePolled<Agent[]>("/agents", 2000);
  const { data: metrics } = usePolled<Metrics>("/metrics", 2000);
  const { data: config } = usePolled<Config>("/config", 5000);
  const { data: feed } = usePolled<Feed>("/feed", 2000);
  const { decisions } = useDecisionStream(60);

  const thetaLow = config?.theta_low ?? 0.5;
  const thetaHigh = config?.theta_high ?? 0.65;

  // Ground truth, and only because the traffic is simulated. Against real
  // traffic this set is always empty - which is the entire reason the
  // scheduler has to guess.
  const compromised = useMemo(
    () => new Set(feed?.compromised_now ?? []),
    [feed],
  );

  const distrusted = agents?.filter((a) => a.trust < thetaLow).length ?? 0;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink-200">Fleet</h1>
          <p className="mt-0.5 text-[11px] text-ink-400">
            Every agent, least trusted first. Trust decays toward 0.5 when an
            agent goes quiet — a past verification stops counting.
          </p>
        </div>
        <FeedControls onChange={refresh} />
      </div>

      {error && <ErrorNote message={error} />}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Agents" value={metrics?.agents ?? "—"} />
        <Stat
          label="Below θ_low"
          value={distrusted}
          tone={distrusted > 0 ? "bad" : "good"}
          hint={`θ_low = ${thetaLow.toFixed(2)}`}
        />
        <Stat
          label="Verifications"
          value={metrics?.verifications ?? "—"}
          hint={metrics ? `${metrics.enforced} enforced` : undefined}
        />
        <Stat
          label="Budget spent"
          value={metrics ? num(metrics.budget_per_1k_steps) : "—"}
          hint="per 1,000 steps"
        />
        <Stat
          label="Mean trust"
          value={metrics ? num(metrics.mean_trust, 3) : "—"}
        />
      </div>

      <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
        <Panel
          title="Agents"
          subtitle={
            feed?.running
              ? "The compromised column is simulator ground truth. A real deployment does not have it — that is what the trust score is estimating."
              : undefined
          }
        >
          {!agents?.length ? (
            <Empty>
              No agents yet. Start the simulated feed, or POST an envelope to{" "}
              <code className="text-ink-300">/observe</code>.
            </Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12px]">
                <thead>
                  <tr className="border-b border-ink-700 text-[10px] uppercase tracking-wider text-ink-400">
                    <th className="pb-2 pr-3 font-normal">Agent</th>
                    <th className="pb-2 pr-3 font-normal">Trust</th>
                    <th className="pb-2 pr-3 font-normal">Recent</th>
                    <th className="pb-2 pr-3 font-normal">State</th>
                    <th className="pb-2 pr-3 text-right font-normal">Steps</th>
                    <th className="pb-2 text-right font-normal">Verifies</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((agent) => (
                    <AgentRow
                      key={agent.agent_id}
                      agent={agent}
                      thetaLow={thetaLow}
                      thetaHigh={thetaHigh}
                      compromised={compromised.has(agent.agent_id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Live decisions" subtitle="Most recent first.">
          {!decisions.length ? (
            <Empty>Waiting for traffic.</Empty>
          ) : (
            <ul className="max-h-[420px] space-y-1 overflow-y-auto">
              {decisions.map((d, i) => (
                <li
                  key={`${d.agent_id}-${d.timestamp}-${i}`}
                  className="flex items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-ink-850"
                >
                  <span
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                      d.action === "verify" ? "bg-orange-400" : "bg-ink-600"
                    }`}
                  />
                  <Link
                    href={`/agents/${encodeURIComponent(d.agent_id)}`}
                    className="w-24 shrink-0 truncate text-ink-300 hover:text-sky-400"
                  >
                    {d.agent_id}
                  </Link>
                  <span className="tnum text-ink-400">{d.trust.toFixed(3)}</span>
                  <span className="ml-auto text-ink-400">{d.reason}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

function AgentRow({
  agent,
  thetaLow,
  thetaHigh,
  compromised,
}: {
  agent: Agent;
  thetaLow: number;
  thetaHigh: number;
  compromised: boolean;
}) {
  const [spark, setSpark] = useState<number[]>([]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const points = await api.get<TrajectoryPoint[]>(
          `/agents/${encodeURIComponent(agent.agent_id)}/trajectory?limit=60`,
        );
        if (!cancelled) setSpark(points.map((p) => p.trust));
      } catch {
        // A missing sparkline is not worth surfacing an error for.
      }
    };
    load();
    const handle = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(handle);
    };
  }, [agent.agent_id]);

  return (
    <tr className="border-b border-ink-850/80 last:border-0 hover:bg-ink-850/50">
      <td className="py-2 pr-3">
        <Link
          href={`/agents/${encodeURIComponent(agent.agent_id)}`}
          className="text-ink-200 hover:text-sky-400"
        >
          {agent.agent_id}
        </Link>
      </td>
      <td className="py-2 pr-3">
        <TrustBar trust={agent.trust} thetaLow={thetaLow} thetaHigh={thetaHigh} />
      </td>
      <td className="py-2 pr-3">
        <Sparkline values={spark} thetaLow={thetaLow} />
      </td>
      <td className="py-2 pr-3">
        <div className="flex flex-wrap items-center gap-1">
          {compromised && (
            <Badge tone="bad" title="Simulator ground truth, not an inference.">
              compromised
            </Badge>
          )}
          {!agent.armed && (
            <Badge
              tone="neutral"
              title="Already verified on the way down. Waits for trust to clear θ_high before it can fire again."
            >
              disarmed
            </Badge>
          )}
        </div>
      </td>
      <td className="py-2 pr-3 text-right tnum text-ink-400">
        {agent.decisions.toLocaleString()}
      </td>
      <td className="py-2 text-right tnum text-ink-300">
        {agent.verifications}
      </td>
    </tr>
  );
}
