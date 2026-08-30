"use client";

import { useMemo, useState } from "react";
import type { FrontierPoint, TrajectoryPoint } from "@/lib/types";

/**
 * Charts are hand-rolled SVG rather than a charting library. There are only
 * three of them, they need specific annotations (threshold lines, verification
 * markers, a hysteresis band) that generic components fight against, and it
 * keeps the console's dependency list at React plus Next.
 */

function scale(value: number, lo: number, hi: number, to0: number, to1: number) {
  if (hi === lo) return (to0 + to1) / 2;
  return to0 + ((value - lo) / (hi - lo)) * (to1 - to0);
}

export function Sparkline({
  values,
  width = 120,
  height = 24,
  thetaLow = 0.5,
}: {
  values: number[];
  width?: number;
  height?: number;
  thetaLow?: number;
}) {
  if (values.length < 2) {
    return <div style={{ width, height }} className="text-ink-600">—</div>;
  }
  const path = values
    .map((v, i) => {
      const x = scale(i, 0, values.length - 1, 1, width - 1);
      const y = scale(v, 0, 1, height - 1, 1);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const last = values[values.length - 1];
  const stroke = last < thetaLow ? "#fb7185" : last < 0.65 ? "#fbbf24" : "#34d399";

  return (
    <svg width={width} height={height} className="overflow-visible">
      <line
        x1={0}
        x2={width}
        y1={scale(thetaLow, 0, 1, height - 1, 1)}
        y2={scale(thetaLow, 0, 1, height - 1, 1)}
        stroke="#333b4d"
        strokeDasharray="2 2"
      />
      <path d={path} fill="none" stroke={stroke} strokeWidth={1.25} />
    </svg>
  );
}

export function TrajectoryChart({
  points,
  thetaLow,
  thetaHigh,
  height = 260,
}: {
  points: TrajectoryPoint[];
  thetaLow: number;
  thetaHigh: number;
  height?: number;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 900;
  const pad = { top: 12, right: 12, bottom: 24, left: 36 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const { trustPath, riskPath, verifies } = useMemo(() => {
    const x = (i: number) =>
      pad.left + scale(i, 0, Math.max(1, points.length - 1), 0, plotW);
    const y = (v: number) => pad.top + scale(v, 0, 1, plotH, 0);

    const line = (get: (p: TrajectoryPoint) => number) =>
      points
        .map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(get(p)).toFixed(1)}`)
        .join(" ");

    return {
      trustPath: line((p) => p.trust),
      riskPath: line((p) => p.p),
      verifies: points
        .map((p, i) => ({ p, i }))
        .filter(({ p }) => p.action === "verify")
        .map(({ i }) => x(i)),
    };
  }, [points, plotW, plotH, pad.left, pad.top]);

  if (points.length < 2) {
    return (
      <div className="py-16 text-center text-[12px] text-ink-400">
        Not enough decisions yet to draw a trajectory.
      </div>
    );
  }

  const yFor = (v: number) => pad.top + scale(v, 0, 1, plotH, 0);
  const hovered = hover === null ? null : points[hover];

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const rel = ((e.clientX - rect.left) / rect.width) * width;
          const i = Math.round(
            scale(rel, pad.left, pad.left + plotW, 0, points.length - 1),
          );
          setHover(Math.max(0, Math.min(points.length - 1, i)));
        }}
      >
        {/* Hysteresis band: between these two lines the trigger neither fires
            nor re-arms. */}
        <rect
          x={pad.left}
          y={yFor(thetaHigh)}
          width={plotW}
          height={Math.max(0, yFor(thetaLow) - yFor(thetaHigh))}
          fill="#fbbf24"
          opacity={0.06}
        />

        {[0, 0.25, 0.5, 0.75, 1].map((v) => (
          <g key={v}>
            <line
              x1={pad.left}
              x2={pad.left + plotW}
              y1={yFor(v)}
              y2={yFor(v)}
              stroke="#1c212c"
            />
            <text x={4} y={yFor(v) + 3} fill="#6b7689" fontSize={9}>
              {v.toFixed(2)}
            </text>
          </g>
        ))}

        <line
          x1={pad.left}
          x2={pad.left + plotW}
          y1={yFor(thetaLow)}
          y2={yFor(thetaLow)}
          stroke="#fb7185"
          strokeDasharray="4 3"
          strokeWidth={1}
        />
        <line
          x1={pad.left}
          x2={pad.left + plotW}
          y1={yFor(thetaHigh)}
          y2={yFor(thetaHigh)}
          stroke="#fbbf24"
          strokeDasharray="4 3"
          strokeWidth={1}
        />

        {verifies.map((x, i) => (
          <line
            key={i}
            x1={x}
            x2={x}
            y1={pad.top}
            y2={pad.top + plotH}
            stroke="#f97316"
            strokeWidth={1.5}
            opacity={0.85}
          />
        ))}

        <path d={riskPath} fill="none" stroke="#64748b" strokeWidth={1} opacity={0.5} />
        <path d={trustPath} fill="none" stroke="#38bdf8" strokeWidth={1.75} />

        {hover !== null && (
          <line
            x1={pad.left + scale(hover, 0, points.length - 1, 0, plotW)}
            x2={pad.left + scale(hover, 0, points.length - 1, 0, plotW)}
            y1={pad.top}
            y2={pad.top + plotH}
            stroke="#94a0b4"
            strokeWidth={0.75}
          />
        )}
      </svg>

      <div className="mt-2 flex flex-wrap items-center gap-4 text-[10px] text-ink-400">
        <Legend colour="#38bdf8">trust</Legend>
        <Legend colour="#64748b">risk p</Legend>
        <Legend colour="#f97316">verification</Legend>
        <Legend colour="#fb7185">θ_low {thetaLow.toFixed(2)}</Legend>
        <Legend colour="#fbbf24">θ_high {thetaHigh.toFixed(2)}</Legend>
      </div>

      {hovered && (
        <div className="mt-2 rounded border border-ink-700 bg-ink-850 px-3 py-1.5 text-[11px] tnum text-ink-300">
          trust {hovered.trust.toFixed(3)} · p {hovered.p.toFixed(3)} ·{" "}
          {hovered.action} ({hovered.reason})
        </div>
      )}
    </div>
  );
}

function Legend({ colour, children }: { colour: string; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className="inline-block h-0.5 w-4"
        style={{ backgroundColor: colour }}
      />
      {children}
    </span>
  );
}

export function FrontierChart({
  points,
  height = 340,
}: {
  points: FrontierPoint[];
  height?: number;
}) {
  const width = 760;
  const pad = { top: 16, right: 20, bottom: 44, left: 56 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const adaptive = points.filter((p) => p.policy === "adaptive");
  const periodic = points.filter((p) => p.policy === "periodic");
  const maxBudget = Math.max(...points.map((p) => p.budget_per_1k_steps), 1) * 1.05;

  const x = (b: number) => pad.left + scale(b, 0, maxBudget, 0, plotW);
  const y = (e: number) => pad.top + scale(e, 0, 1, plotH, 0);

  const series = (rows: FrontierPoint[]) =>
    [...rows]
      .sort((a, b) => a.budget_per_1k_steps - b.budget_per_1k_steps)
      .map(
        (p, i) =>
          `${i === 0 ? "M" : "L"}${x(p.budget_per_1k_steps).toFixed(1)},${y(p.exposure).toFixed(1)}`,
      )
      .join(" ");

  return (
    <div>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full">
        {[0, 0.25, 0.5, 0.75, 1].map((v) => (
          <g key={v}>
            <line x1={pad.left} x2={pad.left + plotW} y1={y(v)} y2={y(v)} stroke="#1c212c" />
            <text x={8} y={y(v) + 3} fill="#6b7689" fontSize={10}>
              {(v * 100).toFixed(0)}%
            </text>
          </g>
        ))}

        {[0, 0.25, 0.5, 0.75, 1].map((f) => {
          const b = maxBudget * f;
          return (
            <text key={f} x={x(b)} y={height - 24} fill="#6b7689" fontSize={10} textAnchor="middle">
              {b.toFixed(0)}
            </text>
          );
        })}

        <path d={series(periodic)} fill="none" stroke="#fb7185" strokeWidth={1.5} strokeDasharray="5 3" />
        <path d={series(adaptive)} fill="none" stroke="#38bdf8" strokeWidth={2} />

        {periodic.map((p) => (
          <g key={`p-${p.setting}`}>
            <rect
              x={x(p.budget_per_1k_steps) - 3}
              y={y(p.exposure) - 3}
              width={6}
              height={6}
              fill="#fb7185"
            />
            <title>{`periodic ${p.setting} — budget ${p.budget_per_1k_steps.toFixed(2)}/1k, exposure ${(p.exposure * 100).toFixed(1)}%, false ${p.false_verifications_per_1k_benign.toFixed(2)}/1k`}</title>
          </g>
        ))}
        {adaptive.map((p) => (
          <g key={`a-${p.setting}`}>
            <circle cx={x(p.budget_per_1k_steps)} cy={y(p.exposure)} r={3.5} fill="#38bdf8" />
            <title>{`adaptive ${p.setting} — budget ${p.budget_per_1k_steps.toFixed(2)}/1k, exposure ${(p.exposure * 100).toFixed(1)}%, false ${p.false_verifications_per_1k_benign.toFixed(2)}/1k`}</title>
          </g>
        ))}

        <text
          x={pad.left + plotW / 2}
          y={height - 6}
          fill="#94a0b4"
          fontSize={11}
          textAnchor="middle"
        >
          verification budget (per 1,000 steps) →
        </text>
        <text
          x={-(pad.top + plotH / 2)}
          y={14}
          fill="#94a0b4"
          fontSize={11}
          textAnchor="middle"
          transform="rotate(-90)"
        >
          attacker exposure →
        </text>
      </svg>

      <div className="mt-1 flex items-center gap-5 text-[10px] text-ink-400">
        <Legend colour="#38bdf8">adaptive (θ sweep)</Legend>
        <Legend colour="#fb7185">periodic (k sweep)</Legend>
        <span className="text-ink-500">hover a point for its numbers</span>
      </div>
    </div>
  );
}
