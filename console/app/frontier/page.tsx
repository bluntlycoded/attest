"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { BenchmarkResult, FrontierResult } from "@/lib/types";
import { num, pct } from "@/lib/format";
import { FrontierChart } from "@/components/charts";
import { Button, Empty, ErrorNote, Field, NumberInput, Panel } from "@/components/ui";

export default function FrontierPage() {
  const [sessions, setSessions] = useState(300);
  const [seed, setSeed] = useState(0);
  const [quality, setQuality] = useState(9);
  const [frontier, setFrontier] = useState<FrontierResult | null>(null);
  const [benchmark, setBenchmark] = useState<BenchmarkResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    setBusy(true);
    setError(null);
    const body = {
      sessions,
      seed,
      detector_quality: quality,
      resamples: 100,
    };
    try {
      const [f, b] = await Promise.all([
        api.post<FrontierResult>("/frontier", body),
        api.post<BenchmarkResult>("/benchmark", body),
      ]);
      setFrontier(f);
      setBenchmark(b);
    } catch (err) {
      setError(err instanceof Error ? err.message : "benchmark failed");
    } finally {
      setBusy(false);
    }
  }, [sessions, seed, quality]);

  useEffect(() => {
    run();
    // Run once on mount; afterwards the user drives it with the button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const adaptive = frontier?.points.filter((p) => p.policy === "adaptive") ?? [];
  const periodic = frontier?.points.filter((p) => p.policy === "periodic") ?? [];

  // The headline comparison: pick the best adaptive point, then find the
  // cheapest periodic setting that matches its protection.
  const best = adaptive.length
    ? adaptive.reduce((a, b) => (b.exposure < a.exposure ? b : a))
    : null;
  const matched = best
    ? periodic
        .filter((p) => p.exposure <= best.exposure)
        .sort((a, b) => a.budget_per_1k_steps - b.budget_per_1k_steps)[0]
    : undefined;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-ink-200">
          Budget–exposure frontier
        </h1>
        <p className="mt-0.5 max-w-3xl text-[11px] leading-relaxed text-ink-400">
          What a fixed re-verification schedule costs you. The periodic curve is
          what session expiry and calendar credential rotation actually are —
          a clock that fires regardless of what the agent is doing. Every point
          is measured on generated sessions where ground truth exists, so
          exposure and containment can be computed at all.
        </p>
      </div>

      <Panel title="Run">
        <div className="flex flex-wrap items-end gap-4">
          <div className="w-32">
            <Field label="Sessions">
              <NumberInput
                value={sessions}
                min={1}
                max={5000}
                onChange={(v) => setSessions(Number(v))}
              />
            </Field>
          </div>
          <div className="w-24">
            <Field label="Seed">
              <NumberInput value={seed} onChange={(v) => setSeed(Number(v))} />
            </Field>
          </div>
          <div className="w-40">
            <Field label="Detector quality" hint="higher = cleaner separation">
              <NumberInput
                value={quality}
                step={0.5}
                min={0.5}
                onChange={(v) => setQuality(Number(v))}
              />
            </Field>
          </div>
          <Button tone="primary" onClick={run} disabled={busy}>
            {busy ? "Running…" : "Run benchmark"}
          </Button>
        </div>
      </Panel>

      {error && <ErrorNote message={error} />}

      {best && matched && (
        <div className="rounded-lg border border-sky-900 bg-sky-950/30 px-4 py-3 text-[12px] leading-relaxed text-sky-100">
          At comparable protection ({pct(best.exposure)} exposure), the adaptive
          policy spends{" "}
          <strong className="tnum">{num(best.budget_per_1k_steps)}</strong>{" "}
          verifications per 1,000 steps against the periodic policy&apos;s{" "}
          <strong className="tnum">{num(matched.budget_per_1k_steps)}</strong> —{" "}
          <strong className="tnum">
            {num(matched.budget_per_1k_steps / Math.max(best.budget_per_1k_steps, 1e-9), 1)}×
          </strong>{" "}
          less. It also raises{" "}
          <strong className="tnum">
            {num(best.false_verifications_per_1k_benign, 3)}
          </strong>{" "}
          false verifications per 1,000 benign steps against{" "}
          <strong className="tnum">
            {num(matched.false_verifications_per_1k_benign, 2)}
          </strong>
          . Every one of those is a challenge sent to an agent that was behaving
          perfectly well.
        </div>
      )}

      <Panel title="Frontier">
        {frontier ? (
          <FrontierChart points={frontier.points} />
        ) : (
          <Empty>{busy ? "Running…" : "No results yet."}</Empty>
        )}
      </Panel>

      <Panel
        title="Policy comparison"
        subtitle="All four policies on the same sessions, with 95% session-grouped bootstrap intervals on exposure. Compare the budget column before the exposure column — they are not held equal here."
      >
        {!benchmark ? (
          <Empty>{busy ? "Running…" : "No results yet."}</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-ink-700 text-[10px] uppercase tracking-wider text-ink-400">
                  <th className="pb-2 pr-3 font-normal">Policy</th>
                  <th className="pb-2 pr-3 text-right font-normal">Budget /1k</th>
                  <th className="pb-2 pr-3 text-right font-normal">Exposure</th>
                  <th className="pb-2 pr-3 text-right font-normal">95% CI</th>
                  <th className="pb-2 pr-3 text-right font-normal">Contained</th>
                  <th className="pb-2 pr-3 text-right font-normal">Delay</th>
                  <th className="pb-2 text-right font-normal">False /1k benign</th>
                </tr>
              </thead>
              <tbody>
                {benchmark.results.map((r) => (
                  <tr
                    key={r.policy}
                    className={`border-b border-ink-850/70 last:border-0 ${
                      r.policy === "beta-trust" ? "bg-sky-950/20" : ""
                    }`}
                  >
                    <td className="py-2 pr-3 text-ink-200">{r.policy}</td>
                    <td className="py-2 pr-3 text-right tnum text-ink-300">
                      {num(r.budget_per_1k_steps)}
                    </td>
                    <td className="py-2 pr-3 text-right tnum text-ink-200">
                      {pct(r.exposure)}
                    </td>
                    <td className="py-2 pr-3 text-right tnum text-ink-400">
                      {r.exposure_ci
                        ? `${pct(r.exposure_ci[0], 1)} – ${pct(r.exposure_ci[1], 1)}`
                        : "—"}
                    </td>
                    <td className="py-2 pr-3 text-right tnum text-ink-300">
                      {pct(r.containment)}
                    </td>
                    <td className="py-2 pr-3 text-right tnum text-ink-400">
                      {num(r.median_onset_delay, 1)}
                    </td>
                    <td className="py-2 text-right tnum text-ink-300">
                      {num(r.false_verifications_per_1k_benign, 3)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <p className="max-w-3xl text-[11px] leading-relaxed text-ink-400">
        These sessions are synthetic and the detector is modelled, so what is
        measured here is the <em>scheduler</em>, holding perception fixed. It is
        not evidence about how well any risk model detects real compromise. Drop
        detector quality to 1.5 and the trust layer degrades badly — the
        recurrence treats p as an expected count of bad evidence, so it needs
        calibrated probabilities to behave.
      </p>
    </div>
  );
}
