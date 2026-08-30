"use client";

import { useEffect, useState } from "react";
import { api, usePolled } from "@/lib/api";
import type { Catalog, Config } from "@/lib/types";
import { duration, num } from "@/lib/format";
import { Button, ErrorNote, Field, NumberInput, Panel } from "@/components/ui";

/**
 * Parameters are edited through a stated requirement - "how long should a
 * misbehaving agent take to earn trust back" - rather than as a raw decay
 * constant. That is the whole argument for the closed-form trust layer: an
 * operator can set it from policy instead of from a validation curve.
 */
export default function SettingsPage() {
  const { data: config, error, refresh } = usePolled<Config>("/config", 5000);
  const { data: catalog } = usePolled<Catalog>("/catalog", 10000);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (config && Object.keys(draft).length === 0) {
      setDraft({
        recovery_seconds: String(config.recovery_seconds),
        theta_low: String(config.theta_low),
        theta_high: String(config.theta_high),
        cooldown_seconds: String(config.cooldown_seconds),
        w: String(config.w),
        gamma: String(config.gamma),
        warmup_events: String(config.warmup_events),
        budget_per_1k_steps:
          config.budget_per_1k_steps === null
            ? ""
            : String(config.budget_per_1k_steps),
      });
    }
  }, [config, draft]);

  const set = (key: string) => (value: string) => {
    setDraft((d) => ({ ...d, [key]: value }));
    setSaved(false);
  };

  const save = async () => {
    setBusy(true);
    setSaveError(null);
    try {
      const body: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(draft)) {
        if (key === "budget_per_1k_steps") continue;
        if (value !== "") body[key] = Number(value);
      }
      if (draft.budget_per_1k_steps === "") {
        body.unlimited_budget = true;
      } else {
        body.budget_per_1k_steps = Number(draft.budget_per_1k_steps);
      }
      await api.put<Config>("/config", body);
      setSaved(true);
      refresh();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : "could not save");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-ink-200">Settings</h1>
        <p className="mt-0.5 max-w-3xl text-[11px] leading-relaxed text-ink-400">
          Five parameters govern everything the deployed system does. Trust
          state survives a change — it lives in the store, not the engine —
          though altering γ does re-interpret the evidence already accumulated.
        </p>
      </div>

      {error && <ErrorNote message={error} />}
      {saveError && <ErrorNote message={saveError} />}

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel
          title="Trust"
          subtitle="How quickly trust burns under bad evidence, and how slowly it rebuilds."
        >
          <div className="space-y-4">
            <Field
              label="Recovery time (seconds)"
              hint="How long a fully distrusted agent under clean traffic takes to become trusted again. Sets the step interval."
            >
              <NumberInput
                value={draft.recovery_seconds ?? ""}
                min={0.001}
                onChange={set("recovery_seconds")}
              />
            </Field>
            <Field
              label="w — misbehaviour weight"
              hint="Above 1, bad evidence counts for more than good. This is the burn-fast, forgive-slow asymmetry."
            >
              <NumberInput value={draft.w ?? ""} step={0.5} min={0.1} onChange={set("w")} />
            </Field>
            <Field
              label="γ — forgetting factor"
              hint="How much history the score retains per step interval."
            >
              <NumberInput
                value={draft.gamma ?? ""}
                step={0.01}
                min={0.01}
                max={0.99}
                onChange={set("gamma")}
              />
            </Field>
            <Field
              label="Warm-up events"
              hint="Before this many messages, a new agent's novelty signals are damped — everything is new to it by construction."
            >
              <NumberInput
                value={draft.warmup_events ?? ""}
                step={1}
                min={0}
                onChange={set("warmup_events")}
              />
            </Field>
          </div>
        </Panel>

        <Panel
          title="Policy"
          subtitle="When a verification actually fires, and how much verification you are willing to pay for."
        >
          <div className="space-y-4">
            <Field
              label="θ_low — verify threshold"
              hint="Trust below this fires a verification."
            >
              <NumberInput
                value={draft.theta_low ?? ""}
                step={0.05}
                min={0}
                max={1}
                onChange={set("theta_low")}
              />
            </Field>
            <Field
              label="θ_high — re-arm threshold"
              hint="A spent trigger re-arms only once trust climbs back above this. The gap is what stops the policy chattering at a boundary."
            >
              <NumberInput
                value={draft.theta_high ?? ""}
                step={0.05}
                min={0}
                max={1}
                onChange={set("theta_high")}
              />
            </Field>
            <Field
              label="Cooldown (seconds)"
              hint="Minimum gap between two verifications of the same agent."
            >
              <NumberInput
                value={draft.cooldown_seconds ?? ""}
                step={0.1}
                min={0}
                onChange={set("cooldown_seconds")}
              />
            </Field>
            <Field
              label="Budget (verifications per 1,000 steps)"
              hint="Leave blank for unlimited. This is the constraint every reported number should be read against."
            >
              <NumberInput
                value={draft.budget_per_1k_steps ?? ""}
                step={0.5}
                min={0.01}
                onChange={set("budget_per_1k_steps")}
              />
            </Field>
          </div>
        </Panel>
      </div>

      <div className="flex items-center gap-3">
        <Button tone="primary" onClick={save} disabled={busy}>
          {busy ? "Saving…" : "Apply"}
        </Button>
        {saved && <span className="text-[11px] text-emerald-400">Applied.</span>}
      </div>

      {catalog && (
        <Panel
          title="Tool catalogue"
          subtitle="What each tool is declared to do. This is the operator's word, never the agent's - a tool description arrives over the same channel as the request, and an agent able to call its own action read-only would. Anything not listed is treated as irreversible and sensitive, so an unknown tool escalates rather than sails through."
        >
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="border-b border-ink-700 text-[10px] uppercase tracking-wider text-ink-400">
                <th className="pb-2 pr-3 font-normal">Tool</th>
                <th className="pb-2 pr-3 font-normal">Reversibility</th>
                <th className="pb-2 pr-3 text-right font-normal">Magnitude</th>
                <th className="pb-2 pr-3 font-normal">Sensitive</th>
                <th className="pb-2 font-normal">Description</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(catalog.tools).map(([name, risk]) => (
                <tr key={name} className="border-b border-ink-850/70 last:border-0">
                  <td className="py-2 pr-3 text-ink-200">{name}</td>
                  <td className="py-2 pr-3">
                    <span
                      className={
                        risk.reversibility === "irreversible" ||
                        risk.reversibility === "unknown"
                          ? "text-rose-400"
                          : risk.reversibility === "recoverable"
                            ? "text-amber-400"
                            : "text-emerald-400"
                      }
                    >
                      {risk.reversibility}
                    </span>
                  </td>
                  <td className="py-2 pr-3 text-right tnum text-ink-300">
                    {num(risk.magnitude, 2)}
                  </td>
                  <td className="py-2 pr-3 text-ink-400">
                    {risk.sensitive ? "yes" : "-"}
                  </td>
                  <td className="py-2 text-ink-400">{risk.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {config && (
        <Panel title="In effect now">
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-[12px] md:grid-cols-3">
            <Row label="step interval" value={duration(config.step_seconds)} />
            <Row label="evidence half-life" value={duration(config.half_life_seconds)} />
            <Row label="recovery time" value={duration(config.recovery_seconds)} />
            <Row label="cooldown" value={duration(config.cooldown_seconds)} />
            <Row
              label="budget"
              value={
                config.budget_per_1k_steps === null
                  ? "unlimited"
                  : `${num(config.budget_per_1k_steps)} / 1k steps`
              }
            />
            <Row label="mode" value={config.shadow ? "shadow" : "enforcing"} />
          </div>
          <p className="mt-4 max-w-3xl text-[11px] leading-relaxed text-ink-400">
            The step interval should sit close to how often one agent actually
            sends a message. Set far above it and evidence accumulates to a
            level no realistic compromise episode can overcome, and the trigger
            silently never fires. Starting the simulated feed tunes this
            automatically.
          </p>
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
