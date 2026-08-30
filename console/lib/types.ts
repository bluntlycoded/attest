/** Mirrors service/schemas.py. Keep the two in step. */

export type Action = "observe" | "verify";

/**
 * Why the policy reached its decision. Useful in the decision stream because
 * it distinguishes "this agent is fine" from "we wanted to verify but could
 * not" - which are very different operationally.
 */
export type Reason =
  | "trusted"
  | "disarmed"
  | "cooldown"
  | "budget_exhausted"
  | "below_threshold";

export interface Decision {
  agent_id: string;
  timestamp: number;
  p: number;
  /** The sender's own trust. */
  trust: number;
  action: Action;
  reason: Reason;
  enforced: boolean;
  /** Trust of the whole delegation chain; equals `trust` when undelegated. */
  effective_trust: number | null;
  /** Who a verification is aimed at - the chain's weakest link. */
  target: string | null;
  /** Delegation chain, root principal first, sender last. */
  chain: string[];
}

export interface Agent {
  agent_id: string;
  trust: number;
  updated_at: number | null;
  armed: boolean;
  cooldown_until: number;
  decisions: number;
  verifications: number;
}

export interface TrajectoryPoint {
  timestamp: number;
  p: number;
  trust: number;
  action: string;
  reason: string;
}

export interface Config {
  gamma: number;
  w: number;
  step_seconds: number;
  recovery_seconds: number;
  half_life_seconds: number;
  theta_low: number;
  theta_high: number;
  cooldown_seconds: number;
  budget_per_1k_steps: number | null;
  shadow: boolean;
  warmup_events: number;
}

export interface Metrics {
  steps: number;
  verifications: number;
  enforced: number;
  budget_per_1k_steps: number;
  mean_trust: number;
  agents: number;
  first_seen: number | null;
  last_seen: number | null;
  reasons: Record<string, number>;
  adapter_unknowns: Record<string, number>;
}

export interface PolicyResult {
  policy: string;
  exposure: number;
  exposure_ci: [number, number] | null;
  containment: number;
  median_onset_delay: number | null;
  budget_per_1k_steps: number;
  false_verifications_per_1k_benign: number;
  episodes: number;
  steps: number;
}

export interface BenchmarkResult {
  config: Record<string, unknown>;
  results: PolicyResult[];
}

export interface FrontierPoint {
  policy: "adaptive" | "periodic";
  setting: string;
  budget_per_1k_steps: number;
  exposure: number;
  false_verifications_per_1k_benign: number;
}

export interface FrontierResult {
  config: Record<string, unknown>;
  points: FrontierPoint[];
}

export interface Feed {
  running: boolean;
  agents: number;
  steps_per_second: number;
  emitted: number;
  /** Ground truth, available only because the traffic is simulated. */
  compromised_now: string[];
}

export interface Health {
  status: string;
  agents: number;
  shadow: boolean;
  feed_running: boolean;
  stream_subscribers: number;
}
