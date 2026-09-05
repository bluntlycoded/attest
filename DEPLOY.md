# Hosting Attest on Render

Two services from one blueprint: the FastAPI service and the Next console.
[`render.yaml`](render.yaml) declares both.

The console is a browser app with no server of its own — every page is a client
component and every byte it shows comes from the service over `fetch`. That
creates a small ordering problem, because the console needs a token that does
not exist until the service is running. Steps 1–6 walk through it in the order
that works.

Read [The console's token is public](#the-consoles-token-is-public) before you
hand anyone the URL.

---

## 1. Connect the repo

`bluntlycoded/attest` is private, so Render needs explicit access to it.

At [dashboard.render.com](https://dashboard.render.com) → **New** → **Blueprint**
→ connect GitHub → grant access to `bluntlycoded/attest` specifically (not "all
repositories") → select it. Render finds `render.yaml` at the root.

Name the blueprint group whatever you like and click **Apply**.

## 2. Let both services build

Render creates `attest-service` (Docker) and `attest-console` (Node).

The service builds an image and comes up healthy. The console builds and comes
up **broken** — it has no token yet, so every panel will show an error. That is
expected; step 5 fixes it.

`render.yaml` sets no `healthCheckPath` on purpose. Every route on the service
requires a bearer token, so a health probe would get a 401 and Render would mark
a perfectly working deploy as failed. Render falls back to checking the port is
bound, which is the right check here.

First Docker build takes 3–5 minutes.

## 3. Read the bootstrap key

Render generated it (`generateValue: true`), so it is not in the repo and never
was.

**attest-service** → **Environment** → reveal `ATTEST_BOOTSTRAP_KEY`. Copy it.

```bash
export BOOTSTRAP="paste-it-here"
export SERVICE="https://attest-service.onrender.com"
```

Confirm the service is alive and refusing anonymous callers:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' $SERVICE/health          # 401
curl -sS $SERVICE/health -H "Authorization: Bearer $BOOTSTRAP"     # {"status":"ok",...}
```

## 4. Mint an approver key for the console

The bootstrap key is an admin key. Do not put it in the console — see below.

```bash
curl -sS -X POST $SERVICE/keys \
  -H "Authorization: Bearer $BOOTSTRAP" \
  -H 'Content-Type: application/json' \
  -d '{"role":"approver","label":"console"}'
```

The token comes back **once**. Only a SHA-256 digest is stored, so losing it
means minting another rather than recovering this one.

## 5. Give the console its token

**attest-console** → **Environment** → add:

| Key | Value |
| --- | --- |
| `NEXT_PUBLIC_ATTEST_TOKEN` | the approver token from step 4 |

`NEXT_PUBLIC_ATTEST_API` is already set by the blueprint.

Saving triggers a rebuild, and it has to: `NEXT_PUBLIC_*` values are compiled
into the JavaScript bundle at build time, not read at runtime. Changing this
token later always means a redeploy, never just a restart.

## 6. Check CORS lines up

`render.yaml` pre-fills the service's `ATTEST_CORS_ORIGINS` with
`https://attest-console.onrender.com`, which is right as long as you kept the
default names. If Render appended a suffix to avoid a collision, or you renamed
either service, fix `ATTEST_CORS_ORIGINS` on **attest-service** to the console's
actual origin — scheme included, no trailing slash — and redeploy it.

Open the console. Panels load, and the decisions page shows a live stream
indicator once SSE connects.

---

## Seeding it with something to look at

A fresh deploy has an empty fleet. `make demo` targets `localhost`, so against a
hosted service run its calls directly. Start the simulated traffic:

```bash
curl -sS -X POST $SERVICE/feed/start \
  -H "Authorization: Bearer $BOOTSTRAP" -H 'Content-Type: application/json' \
  -d '{"agents":14,"steps_per_second":40,"seed":7,"auto_tune":true}'
```

Then drive one agent into a hold:

```bash
curl -sS -X POST $SERVICE/gateway/evaluate \
  -H "Authorization: Bearer $BOOTSTRAP" -H 'Content-Type: application/json' \
  -d '{"agent_id":"svc-billing","tool":"wire_transfer","resource":"acct-9912",
       "arguments":{"amount":50000},"intent":"pay_invoice"}'
```

The feed keeps running server-side, so the console has live traffic whenever
anyone opens it.

---

## Plans, and what the free tier actually costs you

`render.yaml` asks for **Starter** on both ($7/month each). That is deliberate,
and it is the one place free is not merely slower but wrong:

- **Free has no persistent disk.** The service keeps trust state and the
  approval queue in memory alongside a SQLite file. Without a disk, every
  restart and every deploy starts from an empty fleet.
- **Free sleeps after 15 minutes idle**, with a ~50 second cold start. For a
  demo link someone else opens on their own schedule, that is a minute of
  spinner followed by an empty dashboard.

If you want to spend nothing: set both to `free`, drop the `disk:` block (Render
rejects a disk on a free plan), and re-seed with the curl calls above
immediately before anyone looks. The console is stateless and is genuinely fine
on free.

Only ever run **one instance** of the service. Scaling it horizontally gives
each instance its own approval queue and its own SQLite file, so an approval
raised by one is invisible to the others.

---

## The console's token is public

`NEXT_PUBLIC_*` is compiled into the bundle. Whatever token the console holds is
readable by anyone who opens devtools on the deployed page. That is a property
of browser apps, not a flaw here — but two consequences are worth being
deliberate about.

**Approver, never admin.** An admin token in the bundle hands any visitor the
ability to rewrite the thresholds that decide what reaches a reviewer — that is,
the ability to stop being asked. That is worse than having no gate, because the
gate is still trusted.

**Three parts of the console need admin and will return 403 under an approver
key**: Settings (`PUT /config`), the feed start/stop controls, and Reset. The
approval queue, decisions, frontier and the oversight table all work normally.
For a public demo, either accept those three being inert — the curl calls above
cover what they do — or put the console behind Render's IP allowlist or an
auth proxy and only then give it an admin token.

**Rotate it like any other secret.** `EventSource` cannot set headers, so the
SSE stream carries the token as a query parameter, which puts it in access logs.

---

## Elsewhere

The same two pieces deploy anywhere that runs a container plus anywhere that
runs Next. Fly.io needs `fly volumes create` mounted at `/app/data` and
`min_machines_running = 1`. Vercel works for the console (root directory
`console`, same two `NEXT_PUBLIC_` variables) but not for the service, which
needs a stable process and a writable disk.

## When something is wrong

| Symptom | Cause |
| --- | --- |
| Every panel errors, browser console says CORS | `ATTEST_CORS_ORIGINS` does not match the console origin exactly |
| Every panel errors with 401 | `NEXT_PUBLIC_ATTEST_TOKEN` unset, or set after the last build |
| Settings and feed controls 403 | Working as intended — the console holds an approver key |
| Stream indicator never turns green | The token is wrong for the stream too; check `/decisions/stream?token=…` directly |
| Dashboard empty after a redeploy | Free plan, no disk. See the plans section |
