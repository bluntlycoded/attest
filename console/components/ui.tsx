"use client";

import type { ReactNode } from "react";
import { BAND_BG, BAND_TEXT, trustBand } from "@/lib/format";

export function Panel({
  title,
  subtitle,
  right,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-ink-700 bg-ink-900 ${className}`}
    >
      {(title || right) && (
        <header className="flex items-start justify-between gap-4 border-b border-ink-700 px-4 py-3">
          <div>
            {title && (
              <h2 className="text-[13px] font-semibold text-ink-200">{title}</h2>
            )}
            {subtitle && (
              <p className="mt-0.5 max-w-2xl text-[11px] leading-relaxed text-ink-400">
                {subtitle}
              </p>
            )}
          </div>
          {right}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "default" | "good" | "warn" | "bad";
}) {
  const tones = {
    default: "text-ink-200",
    good: "text-emerald-400",
    warn: "text-amber-400",
    bad: "text-rose-400",
  };
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900 px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-ink-400">
        {label}
      </div>
      <div className={`mt-1 text-xl tnum ${tones[tone]}`}>{value}</div>
      {hint && <div className="mt-1 text-[10px] text-ink-400">{hint}</div>}
    </div>
  );
}

export function TrustBar({
  trust,
  thetaLow = 0.5,
  thetaHigh = 0.65,
  width = 96,
}: {
  trust: number;
  thetaLow?: number;
  thetaHigh?: number;
  width?: number;
}) {
  const band = trustBand(trust, thetaLow, thetaHigh);
  return (
    <div className="flex items-center gap-2">
      <div
        className="relative h-1.5 overflow-hidden rounded-full bg-ink-800"
        style={{ width }}
      >
        <div
          className={`h-full ${BAND_BG[band]}`}
          style={{ width: `${Math.max(0, Math.min(1, trust)) * 100}%` }}
        />
        {/* Verify threshold, so a reader can see how close to firing this is. */}
        <div
          className="absolute top-0 h-full w-px bg-ink-400"
          style={{ left: `${thetaLow * 100}%` }}
        />
      </div>
      <span className={`tnum text-[12px] ${BAND_TEXT[band]}`}>
        {trust.toFixed(3)}
      </span>
    </div>
  );
}

export function Badge({
  children,
  tone = "neutral",
  title,
}: {
  children: ReactNode;
  tone?: "neutral" | "good" | "warn" | "bad" | "info";
  title?: string;
}) {
  const tones = {
    neutral: "border-ink-600 text-ink-300",
    good: "border-emerald-900 bg-emerald-950/60 text-emerald-400",
    warn: "border-amber-900 bg-amber-950/60 text-amber-400",
    bad: "border-rose-900 bg-rose-950/60 text-rose-400",
    info: "border-sky-900 bg-sky-950/60 text-sky-400",
  };
  return (
    <span
      title={title}
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function Button({
  children,
  onClick,
  disabled,
  tone = "default",
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  tone?: "default" | "primary" | "danger";
  type?: "button" | "submit";
}) {
  const tones = {
    default: "border-ink-600 bg-ink-800 hover:bg-ink-700 text-ink-200",
    primary:
      "border-sky-700 bg-sky-900/70 hover:bg-sky-800 text-sky-100",
    danger: "border-rose-800 bg-rose-950/70 hover:bg-rose-900 text-rose-200",
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded border px-3 py-1.5 text-[12px] transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${tones[tone]}`}
    >
      {children}
    </button>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <div className="text-[11px] text-ink-300">{label}</div>
      {hint && <div className="mb-1 text-[10px] text-ink-400">{hint}</div>}
      <div className="mt-1">{children}</div>
    </label>
  );
}

export function NumberInput({
  value,
  onChange,
  step = "any",
  min,
  max,
}: {
  value: number | string;
  onChange: (value: string) => void;
  step?: string | number;
  min?: number;
  max?: number;
}) {
  return (
    <input
      type="number"
      value={value}
      step={step}
      min={min}
      max={max}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded border border-ink-600 bg-ink-850 px-2 py-1.5 text-[12px] tnum text-ink-200 outline-none focus:border-sky-700"
    />
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="py-10 text-center text-[12px] text-ink-400">{children}</div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <div className="rounded border border-rose-900 bg-rose-950/40 px-3 py-2 text-[12px] text-rose-300">
      {message}
      <div className="mt-1 text-[11px] text-rose-400/70">
        Is the service running? <code>uvicorn service.app:app</code>
      </div>
    </div>
  );
}
