"use client";

import Link from "next/link";
import { use } from "react";
import { usePolled } from "@/lib/api";
import type { Agent, Config, TrajectoryPoint } from "@/lib/types";
import { REASON_HELP, duration, num } from "@/lib/format";
import { TrajectoryChart } from "@/components/charts";
import { Badge, Empty, ErrorNote, Panel, Stat, TrustBar } from "@/components/ui";

export default function AgentPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const agentId = decodeURIComponent(id);

  const { data: agent, error } = usePolled<Agent>(
    `/agents/${encodeURIComponent(agentId)}`,
    2000,
  );
  const { data: points } = usePolled<TrajectoryPoint[]>(
    `/agents/${encodeURIComponent(agentId)}/trajectory?limit=400`,
    2000,
  );
  const { data: config } = usePolled<Config>("/config", 5000);

  const thetaLow = config?.theta_low ?? 0.5;
  const thetaHigh = config?.theta_high ?? 0.65;
  const verifications = points?.filter((p) => p.action === "verify") ?? [];

  return (
    <div className="space-y-5">
      <div>
        <Link href="/" className="text-[11px] text-ink-400 hover:text-sky-400">
          ← Fleet
        </Link>
        <h1 className="mt-1 text-lg font-semibold text-ink-200">{agentId}</h1>
      </div>

      {error && <ErrorNote message={error} />}

      {agent && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat
            label="Trust"
            value={agent.trust.toFixed(3)}
            tone={
              agent.trust < thetaLow
                ? "bad"
                : agent.trust < thetaHigh
                  ? "warn"
                  : "good"
            }
            hint={`θ_low ${thetaLow.toFixed(2)} · θ_high ${thetaHigh.toFixed(2)}`}
          />
          <Stat label="Steps observed" value={agent.decisions.toLocaleString()} />
          <Stat label="Verifications" value={agent.verifications} />
          <Stat
            label="Trigger"
            value={agent.armed ? "armed" : "disarmed"}
            tone={agent.armed ? "default" : "warn"}
            hint={
              agent.armed
                ? "Eligible to fire"
                : "Waiting for trust to clear θ_high"
            }
          />
        </div>
      )}

      <Panel
        title="Trust trajectory"
        subtitle="Blue is trust, grey is the per-message risk score, orange marks a verification. The shaded band between the thresholds is the hysteresis gap — inside it the trigger neither fires nor re-arms, which is what stops it chattering around a boundary."
      >
        {points ? (
          <TrajectoryChart
            points={points}
            thetaLow={thetaLow}
            thetaHigh={thetaHigh}
          />
        ) : (
          <Empty>Loading…</Empty>
        )}
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Verifications" subtitle="Every time this agent was challenged.">
          {!verifications.length ? (
            <Empty>This agent has never been verified.</Empty>
          ) : (
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-ink-700 text-[10px] uppercase tracking-wider text-ink-400">
                  <th className="pb-2 pr-3 font-normal">At</th>
                  <th className="pb-2 pr-3 font-normal">Trust</th>
                  <th className="pb-2 font-normal">Reason</th>
                </tr>
              </thead>
              <tbody>
                {verifications.map((v, i) => (
                  <tr key={i} className="border-b border-ink-850/80 last:border-0">
                    <td className="py-1.5 pr-3 tnum text-ink-400">
                      {v.timestamp.toFixed(2)}
                    </td>
                    <td className="py-1.5 pr-3 tnum text-rose-400">
                      {v.trust.toFixed(3)}
                    </td>
                    <td className="py-1.5 text-ink-300">{v.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Recent decisions">
          {!points?.length ? (
            <Empty>No decisions yet.</Empty>
          ) : (
            <ul className="max-h-[300px] space-y-0.5 overflow-y-auto">
              {[...points].reverse().slice(0, 80).map((p, i) => (
                <li
                  key={i}
                  className="flex items-center gap-3 rounded px-1.5 py-1 text-[11px] hover:bg-ink-850"
                >
                  <span className="w-16 shrink-0 tnum text-ink-400">
                    {p.timestamp.toFixed(2)}
                  </span>
                  <span className="w-14 shrink-0 tnum text-ink-300">
                    {p.trust.toFixed(3)}
                  </span>
                  <span className="w-12 shrink-0 tnum text-ink-400">
                    p {p.p.toFixed(2)}
                  </span>
                  <span
                    className="ml-auto text-ink-400"
                    title={REASON_HELP[p.reason]}
                  >
                    {p.reason}
                  </span>
                  {p.action === "verify" && <Badge tone="warn">verify</Badge>}
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      {config && (
        <Panel title="Applied parameters">
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-[12px] md:grid-cols-4">
            <Row label="γ (forgetting)" value={num(config.gamma, 3)} />
            <Row label="w (misbehaviour weight)" value={num(config.w, 2)} />
            <Row label="step interval" value={duration(config.step_seconds)} />
            <Row label="half-life" value={duration(config.half_life_seconds)} />
            <Row label="θ_low" value={num(config.theta_low, 2)} />
            <Row label="θ_high" value={num(config.theta_high, 2)} />
            <Row label="cooldown" value={duration(config.cooldown_seconds)} />
            <Row
              label="budget"
              value={
                config.budget_per_1k_steps === null
                  ? "unlimited"
                  : `${num(config.budget_per_1k_steps)}/1k`
              }
            />
          </div>
        </Panel>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-ink-850 pb-1">
      <span className="text-ink-400">{label}</span>
      <span className="tnum text-ink-200">{value}</span>
    </div>
  );
}
