/** Shared formatting helpers. */

/** Trust bands, used consistently for colour across the console. */
export type TrustBand = "trusted" | "watch" | "distrusted";

export function trustBand(
  trust: number,
  thetaLow = 0.5,
  thetaHigh = 0.65,
): TrustBand {
  if (trust < thetaLow) return "distrusted";
  if (trust < thetaHigh) return "watch";
  return "trusted";
}

export const BAND_TEXT: Record<TrustBand, string> = {
  trusted: "text-emerald-400",
  watch: "text-amber-400",
  distrusted: "text-rose-400",
};

export const BAND_BG: Record<TrustBand, string> = {
  trusted: "bg-emerald-500",
  watch: "bg-amber-500",
  distrusted: "bg-rose-500",
};

export const REASON_LABEL: Record<string, string> = {
  trusted: "trusted",
  disarmed: "disarmed",
  cooldown: "in cooldown",
  budget_exhausted: "budget spent",
  below_threshold: "below threshold",
};

/** Short explanation of each reason, for tooltips. */
export const REASON_HELP: Record<string, string> = {
  trusted: "Trust sits at or above the verify threshold.",
  disarmed:
    "Already verified once on the way down. Waits for trust to clear the re-arm threshold before it can fire again.",
  cooldown: "Verified too recently; the minimum gap has not elapsed.",
  budget_exhausted:
    "The policy wanted to verify but no verification budget was left.",
  below_threshold: "Trust fell below the verify threshold, so a check fired.",
};

export function pct(value: number, digits = 1): string {
  return `${(value * 100).toFixed(digits)}%`;
}

export function num(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toFixed(digits);
}

export function duration(seconds: number): string {
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} h`;
  return `${(seconds / 86400).toFixed(1)} d`;
}

/**
 * Timestamps come from whatever clock produced the traffic, which for the
 * simulator is a monotonic counter rather than wall time. Show elapsed
 * position rather than pretending it is a date.
 */
export function stamp(value: number): string {
  return value.toFixed(2);
}
