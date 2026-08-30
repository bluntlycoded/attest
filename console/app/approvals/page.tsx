"use client";

import { useState } from "react";
import { api, usePolled } from "@/lib/api";
import type { Approval, ApproverStats, DecisionPacket } from "@/lib/types";
import { duration, num, pct } from "@/lib/format";
import { Badge, Button, Empty, ErrorNote, Panel, Stat } from "@/components/ui";

/**
 * The page the whole scheduler exists to feed.
 *
 * Two halves, and the second is the one nothing else in the market has. The
 * queue shows what is waiting on a person. The oversight panel shows whether
 * those people are still reading — a gate that has decayed into a rubber stamp
 * looks identical to a healthy one from every other angle, because the
 * approvals still arrive and the audit log still fills.
 */
export default function ApprovalsPage() {
  const { data: pending, error, refresh } = usePolled<Approval[]>(
    "/approvals",
    3000,
  );
  const { data: approvers } = usePolled<ApproverStats[]>("/approvers", 5000);
  const [selected, setSelected] = useState<string | null>(null);
  const [approver, setApprover] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const rows = pending ?? [];
  const current = rows.find((r) => r.request_id === selected) ?? rows[0] ?? null;
  const hollow = approvers?.filter((a) => a.hollow) ?? [];

  const decide = async (outcome: "approved" | "rejected") => {
    if (!current) return;
    if (!approver.trim()) {
      setFailure("Say who is answering. An approval nobody signed is not evidence.");
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      await api.post(`/approvals/${current.request_id}/decide`, {
        approver: approver.trim(),
        outcome,
      });
      setSelected(null);
      refresh();
    } catch (err) {
      setFailure(err instanceof Error ? err.message : "could not record the answer");
    } finally {
      setBusy(false);
    }
  };

  const sweep = async () => {
    setBusy(true);
    try {
      await api.post("/approvals/sweep");
      refresh();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink-200">Approvals</h1>
          <p className="mt-0.5 max-w-3xl text-[11px] leading-relaxed text-ink-400">
            Actions held for a person. Nothing here runs until it is answered —
            and an unanswered hold expires into a denial, never into permission.
          </p>
        </div>
        <Button onClick={sweep} disabled={busy}>
          Expire overdue
        </Button>
      </div>

      {error && <ErrorNote message={error} />}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Waiting" value={rows.length} tone={rows.length ? "warn" : "default"} />
        <Stat
          label="For an authority"
          value={rows.filter((r) => r.tier === "authority").length}
          hint="consequential and irreversible"
        />
        <Stat label="Reviewers seen" value={approvers?.length ?? 0} />
        <Stat
          label="Gates gone hollow"
          value={hollow.length}
          tone={hollow.length ? "bad" : "good"}
          hint="fast, uniform, near-total approval"
        />
      </div>

      {hollow.length > 0 && (
        <div className="rounded-lg border border-rose-900 bg-rose-950/40 px-4 py-3 text-[12px] leading-relaxed text-rose-200">
          <strong>{hollow.map((h) => h.approver).join(", ")}</strong>{" "}
          {hollow.length === 1 ? "appears" : "appear"} to be approving without
          reading — near-total approval, in almost exactly the same time each
          time. Every approval recorded under that pattern is audit evidence
          that nobody actually looked.
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[1fr_1.4fr]">
        <Panel title="Queue" subtitle="Oldest first.">
          {!rows.length ? (
            <Empty>Nothing is waiting. Agents are working unimpeded.</Empty>
          ) : (
            <ul className="max-h-[520px] space-y-1 overflow-y-auto">
              {rows.map((row) => {
                const active = current?.request_id === row.request_id;
                const overdue = row.expires_at < Date.now() / 1000;
                return (
                  <li key={row.request_id}>
                    <button
                      onClick={() => setSelected(row.request_id)}
                      className={`w-full rounded border px-3 py-2 text-left transition-colors ${
                        active
                          ? "border-sky-800 bg-sky-950/40"
                          : "border-ink-700 hover:bg-ink-850"
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <Badge tone={row.tier === "authority" ? "bad" : "warn"}>
                          {row.tier}
                        </Badge>
                        <span className="text-[12px] text-ink-200">{row.tool}</span>
                        {overdue && <Badge tone="neutral">overdue</Badge>}
                      </div>
                      <div className="mt-1 text-[11px] text-ink-400">
                        {row.agent_id}
                        {row.target !== row.agent_id && (
                          <span className="text-amber-400">
                            {" "}
                            → check {row.target}
                          </span>
                        )}
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>

        <Panel
          title="Decision"
          subtitle="Enough context to answer without guessing. A yes/no prompt with no detail is what turns approval into reflex."
        >
          {!current ? (
            <Empty>Select a request.</Empty>
          ) : (
            <div className="space-y-4">
              <PacketView packet={current.packet} />

              {failure && <ErrorNote message={failure} />}

              <div className="flex flex-wrap items-center gap-3 border-t border-ink-700 pt-4">
                <input
                  value={approver}
                  onChange={(e) => setApprover(e.target.value)}
                  placeholder="who is answering"
                  className="w-48 rounded border border-ink-600 bg-ink-850 px-2 py-1.5 text-[12px] text-ink-200 outline-none focus:border-sky-700"
                />
                <Button
                  tone="primary"
                  onClick={() => decide("approved")}
                  disabled={busy}
                >
                  Approve
                </Button>
                <Button
                  tone="danger"
                  onClick={() => decide("rejected")}
                  disabled={busy}
                >
                  Reject
                </Button>
                <span className="text-[10px] text-ink-400">
                  answers are recorded once and cannot be changed
                </span>
              </div>
            </div>
          )}
        </Panel>
      </div>

      {approvers && approvers.length > 0 && (
        <Panel
          title="Oversight"
          subtitle="Whether each reviewer still appears to be reading. Approving a lot is not the tell — approving a lot, fast, and in the same time every time is."
        >
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="border-b border-ink-700 text-[10px] uppercase tracking-wider text-ink-400">
                <th className="pb-2 pr-3 font-normal">Reviewer</th>
                <th className="pb-2 pr-3 text-right font-normal">Decisions</th>
                <th className="pb-2 pr-3 text-right font-normal">Approved</th>
                <th className="pb-2 pr-3 text-right font-normal">Median time</th>
                <th className="pb-2 pr-3 text-right font-normal">Spread</th>
                <th className="pb-2 font-normal">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {approvers.map((a) => (
                <tr
                  key={a.approver}
                  className={`border-b border-ink-850/70 last:border-0 ${
                    a.hollow ? "bg-rose-950/20" : ""
                  }`}
                >
                  <td className="py-2 pr-3 text-ink-200">{a.approver}</td>
                  <td className="py-2 pr-3 text-right tnum text-ink-400">
                    {a.decisions}
                  </td>
                  <td className="py-2 pr-3 text-right tnum text-ink-300">
                    {pct(a.approval_rate, 0)}
                  </td>
                  <td className="py-2 pr-3 text-right tnum text-ink-300">
                    {duration(a.median_latency)}
                  </td>
                  <td className="py-2 pr-3 text-right tnum text-ink-400">
                    {num(a.latency_cv)}
                  </td>
                  <td className="py-2">
                    {a.hollow ? (
                      <Badge tone="bad">looks hollow</Badge>
                    ) : a.decisions < 20 ? (
                      <span className="text-ink-500">too few to judge</span>
                    ) : (
                      <Badge tone="good">reading</Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}

function PacketView({ packet }: { packet: DecisionPacket }) {
  const delegated = packet.chain.length > 1;
  return (
    <div className="space-y-3">
      <div>
        <div className="text-[15px] text-ink-200">
          <span className="text-sky-400">{packet.agent_id}</span> wants to run{" "}
          <span className="text-amber-300">{packet.tool}</span>
        </div>
        {packet.tool_description && (
          <p className="mt-1 text-[12px] text-ink-300">{packet.tool_description}</p>
        )}
        {packet.resource && (
          <p className="mt-1 text-[12px] text-ink-400">on {packet.resource}</p>
        )}
      </div>

      {packet.drivers.length > 0 ? (
        <div className="rounded border border-amber-900 bg-amber-950/30 px-3 py-2 text-[11px] text-amber-200">
          Escalated because: {packet.drivers.join("; ")}
        </div>
      ) : (
        // Two different reasons to be asked, and a reviewer shown a harmless
        // tool with no explanation will approve it without thinking. This one
        // is not about the action at all.
        <div className="rounded border border-sky-900 bg-sky-950/30 px-3 py-2 text-[11px] text-sky-200">
          The action itself is routine. You are being asked because the{" "}
          <strong>agent</strong> is due a check — its trust fell to{" "}
          {num(packet.effective_trust, 3)} and the scheduler picked this moment
          to spend one.
        </div>
      )}

      {packet.target !== packet.agent_id && (
        <div className="rounded border border-ink-600 bg-ink-850 px-3 py-2 text-[11px] text-ink-300">
          The weak link is <strong className="text-amber-300">{packet.target}</strong>,
          not the sender. Challenging {packet.agent_id} would come back clean and
          contain nothing.
        </div>
      )}

      <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-[12px] md:grid-cols-3">
        <Row label="reversibility" value={packet.reversibility} />
        <Row label="agent trust" value={num(packet.trust, 3)} />
        <Row
          label="chain trust"
          value={delegated ? num(packet.effective_trust, 3) : "—"}
        />
        <Row label="novelty" value={num(packet.novelty, 2)} />
        <Row label="risk score" value={num(packet.risk_score, 2)} />
        <Row label="engine reason" value={packet.reason} />
      </div>

      <div className="text-[10px] text-ink-500">
        arguments sha256 {packet.argument_digest.slice(0, 16)} · not shown, because
        a payload routinely holds exactly the data an approval should not copy
        into a chat channel
      </div>

      {packet.recent.length > 0 && (
        <div>
          <div className="mb-1 text-[10px] uppercase tracking-wider text-ink-400">
            What led here
          </div>
          <ul className="space-y-0.5">
            {packet.recent.map((step, i) => (
              <li key={i} className="flex items-center gap-2 text-[11px]">
                <span
                  className={step.allowed ? "text-emerald-500" : "text-amber-400"}
                >
                  {step.allowed ? "ok  " : "held"}
                </span>
                <span className="text-ink-300">{step.tool}</span>
                <span className="text-ink-500">→ {step.resource || "—"}</span>
              </li>
            ))}
          </ul>
        </div>
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
