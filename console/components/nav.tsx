"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { usePolled } from "@/lib/api";
import type { Approval, Health, WhoAmI } from "@/lib/types";
import { Badge } from "./ui";

const LINKS = [
  { href: "/", label: "Fleet" },
  { href: "/approvals", label: "Approvals" },
  { href: "/decisions", label: "Decisions" },
  { href: "/frontier", label: "Frontier" },
  { href: "/settings", label: "Settings" },
];

export function Nav() {
  const pathname = usePathname();
  const { data: health, error } = usePolled<Health>("/health", 4000);
  const { data: who } = usePolled<WhoAmI>("/whoami", 30000);
  // Surfaced in the nav because a queue nobody looks at is the failure this
  // whole design is trying to avoid.
  const { data: waiting } = usePolled<Approval[]>("/approvals", 5000);

  return (
    <nav className="sticky top-0 z-10 border-b border-ink-700 bg-ink-900/95 backdrop-blur">
      <div className="mx-auto flex max-w-[1400px] items-center gap-6 px-6 py-3">
        <Link href="/" className="flex items-baseline gap-2">
          <span className="text-[15px] font-semibold tracking-tight text-ink-200">
            attest
          </span>
          <span className="hidden text-[10px] text-ink-400 sm:inline">
            when to re-verify, under a budget
          </span>
        </Link>

        <div className="flex items-center gap-1">
          {LINKS.map((link) => {
            const active =
              link.href === "/"
                ? pathname === "/"
                : pathname.startsWith(link.href);
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`rounded px-2.5 py-1 text-[12px] transition-colors ${
                  active
                    ? "bg-ink-800 text-ink-200"
                    : "text-ink-400 hover:text-ink-200"
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </div>

        <div className="ml-auto flex items-center gap-2">
          {waiting && waiting.length > 0 && (
            <Badge tone="warn" title="actions held for a person">
              {waiting.length} waiting
            </Badge>
          )}
          {who && (
            <Badge
              tone="neutral"
              title={`key ${who.key_id} in tenant ${who.tenant_id}`}
            >
              {who.tenant_id} / {who.role}
            </Badge>
          )}
          {error ? (
            <Badge tone="bad" title={error}>
              {error.includes("401") || error.toLowerCase().includes("bearer")
                ? "not authenticated"
                : "service offline"}
            </Badge>
          ) : health ? (
            <>
              <Badge
                tone={health.shadow ? "info" : "warn"}
                title={
                  health.shadow
                    ? "Decisions are recorded but no verifier runs."
                    : "Verifications are being carried out for real."
                }
              >
                {health.shadow ? "shadow" : "enforcing"}
              </Badge>
              {health.feed_running && <Badge tone="good">feed live</Badge>}
              <span className="text-[11px] text-ink-400 tnum">
                {health.agents} agents
              </span>
            </>
          ) : null}
        </div>
      </div>
    </nav>
  );
}
