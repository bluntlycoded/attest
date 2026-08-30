"use client";

import { useState } from "react";
import { api, usePolled } from "@/lib/api";
import type { Feed } from "@/lib/types";
import { Button } from "./ui";

/**
 * Starts and stops the synthetic traffic feed.
 *
 * The feed exists so the console has something to render without the whole
 * SAMACP stack running. It is labelled as simulated wherever it appears,
 * because the compromise flags it produces are ground truth the console would
 * never have against real traffic.
 */
export function FeedControls({ onChange }: { onChange?: () => void }) {
  const { data: feed, refresh } = usePolled<Feed>("/feed", 2000);
  const [busy, setBusy] = useState(false);
  const [agents, setAgents] = useState(12);
  const [rate, setRate] = useState(60);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
      refresh();
      onChange?.();
    } finally {
      setBusy(false);
    }
  };

  const running = feed?.running ?? false;

  return (
    <div className="flex flex-wrap items-center gap-3">
      {!running && (
        <>
          <label className="flex items-center gap-1.5 text-[11px] text-ink-400">
            agents
            <input
              type="number"
              min={1}
              max={200}
              value={agents}
              onChange={(e) => setAgents(Number(e.target.value))}
              className="w-16 rounded border border-ink-600 bg-ink-850 px-1.5 py-1 text-[12px] tnum text-ink-200 outline-none focus:border-sky-700"
            />
          </label>
          <label className="flex items-center gap-1.5 text-[11px] text-ink-400">
            steps/s
            <input
              type="number"
              min={1}
              max={1000}
              value={rate}
              onChange={(e) => setRate(Number(e.target.value))}
              className="w-16 rounded border border-ink-600 bg-ink-850 px-1.5 py-1 text-[12px] tnum text-ink-200 outline-none focus:border-sky-700"
            />
          </label>
        </>
      )}

      {running ? (
        <>
          <span className="text-[11px] tnum text-ink-400">
            {feed?.emitted.toLocaleString()} envelopes ·{" "}
            {feed?.compromised_now.length ?? 0} compromised
          </span>
          <Button onClick={() => act(() => api.post("/feed/stop"))} disabled={busy}>
            Stop feed
          </Button>
        </>
      ) : (
        <Button
          tone="primary"
          disabled={busy}
          onClick={() =>
            act(() =>
              api.post("/feed/start", {
                agents,
                steps_per_second: rate,
                auto_tune: true,
              }),
            )
          }
        >
          Start simulated feed
        </Button>
      )}

      <Button
        tone="danger"
        disabled={busy}
        onClick={() => act(() => api.post("/reset"))}
      >
        Reset
      </Button>
    </div>
  );
}
