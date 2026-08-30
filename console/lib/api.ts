"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { Decision } from "./types";

export const API =
  process.env.NEXT_PUBLIC_ATTEST_API ?? "http://localhost:8317";

/**
 * The service has no anonymous path, so the console has to present a
 * credential. This is a browser-visible value by construction, which means it
 * should be an approver key rather than an admin one - a console that can
 * rewrite the thresholds deciding what reaches its reviewers hands anyone with
 * devtools the ability to stop being asked.
 */
export const TOKEN = process.env.NEXT_PUBLIC_ATTEST_TOKEN ?? "";

function authHeaders(): Record<string, string> {
  return TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...init?.headers,
    },
    cache: "no-store",
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail ?? detail;
    } catch {
      // Non-JSON error body; the status text will have to do.
    }
    throw new ApiError(detail, response.status);
  }
  return response.json() as Promise<T>;
}

export const api = {
  get: <T,>(path: string) => request<T>(path),
  post: <T,>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "POST",
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  put: <T,>(path: string, body: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(body) }),
};

/**
 * Fetch on mount and then poll.
 *
 * Deliberately simple: the console is a single operator watching one service,
 * so a poll is easier to reason about than a cache library. Pass
 * `intervalMs = 0` for one-shot data that only changes when the user acts.
 */
export function usePolled<T>(
  path: string | null,
  intervalMs = 2000,
): { data: T | null; error: string | null; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Held in a ref so the polling effect does not restart on every refresh.
  const tick = useRef(0);
  const [, force] = useState(0);

  const refresh = useCallback(() => {
    tick.current += 1;
    force((n) => n + 1);
  }, []);

  useEffect(() => {
    if (!path) {
      setLoading(false);
      return;
    }
    let cancelled = false;

    const load = async () => {
      try {
        const result = await api.get<T>(path);
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : "could not reach the service",
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    load();
    if (intervalMs <= 0) return () => { cancelled = true; };

    const handle = setInterval(load, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(handle);
    };
  }, [path, intervalMs, tick.current]);

  return { data, error, loading, refresh };
}

/**
 * Subscribe to the server-sent decision stream.
 *
 * Keeps only the most recent `limit` decisions - an operator watching a live
 * fleet wants the tail, and an unbounded buffer would grow without limit.
 */
export function useDecisionStream(limit = 200): {
  decisions: Decision[];
  connected: boolean;
} {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    // EventSource cannot set headers, so the stream carries its token in the
    // query string. That puts a credential in server logs, which is why the
    // console's key should be a narrow one and rotated like any other secret.
    const source = new EventSource(
      `${API}/decisions/stream${TOKEN ? `?token=${encodeURIComponent(TOKEN)}` : ""}`,
    );

    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.onmessage = (event) => {
      try {
        const decision = JSON.parse(event.data) as Decision;
        setDecisions((prev) => [decision, ...prev].slice(0, limit));
      } catch {
        // A malformed frame is not worth tearing the stream down for.
      }
    };

    return () => source.close();
  }, [limit]);

  return { decisions, connected };
}
