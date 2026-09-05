# Hosting Attest

The console is a browser app with no server of its own. Everything it shows
comes from the service over HTTP, so hosting the front end alone gets you a
page that renders and then fails every request. Deploy the service first.

Read [The console's credential is public](#the-consoles-credential-is-public)
before you put either on the open internet.

---

## 1. The service

Anything that runs a container works. The process is stateful — it holds a
SQLite file — so it wants a persistent disk and exactly one instance.

```bash
docker build -t attest-service .
docker run -p 8317:8317 \
  -e ATTEST_BOOTSTRAP_KEY="$(openssl rand -hex 32)" \
  -e ATTEST_CORS_ORIGINS="https://your-console.vercel.app" \
  -v attest-data:/app/data \
  attest-service
```

| Variable | Required | Notes |
| --- | --- | --- |
| `ATTEST_BOOTSTRAP_KEY` | yes | The first admin credential. No default: an unconfigured service is unusable rather than open. |
| `ATTEST_CORS_ORIGINS` | yes | Comma-separated. Must contain the console's exact deployed origin, scheme included, no trailing slash. |
| `ATTEST_DB` | no | Defaults to `/app/data/attest.db` in the image. |
| `PORT` | no | Most hosts inject this. The `CMD` already honours it. |

### Host notes

**Render / Railway** — point at this repo, Docker runtime, attach a disk
mounted at `/app/data`, set the variables above. Both inject `PORT`.

**Fly.io** — `fly launch --no-deploy`, then `fly volumes create attest_data
--size 1` and mount it at `/app/data` in `fly.toml`. Set
`min_machines_running = 1`; a scaled-to-zero machine drops the SSE stream and
loses the in-memory approval queue.

**Not Vercel, not Lambda.** The service holds trust state and the pending
approval queue in memory alongside SQLite, and serves an open SSE connection.
Serverless gives you neither a stable process nor a writable disk.

### After it starts

The bootstrap key is an admin key. Mint a narrower one for the console:

```bash
curl -X POST https://your-service/keys \
  -H "Authorization: Bearer $ATTEST_BOOTSTRAP_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"label":"console","role":"approver"}'
```

The token comes back once and is stored only as a SHA-256 hash. Losing it
means minting another.

---

## 2. The console

Vercel is the path of least resistance — the app has one server-rendered route
(`/agents/[id]`), so a plain static export would need that route rewritten to a
query parameter first.

1. Import the repo at [vercel.com/new](https://vercel.com/new).
2. **Root Directory: `console`.** Framework and build command are detected.
3. Environment variables:

   | Variable | Value |
   | --- | --- |
   | `NEXT_PUBLIC_ATTEST_API` | `https://your-service` — no trailing slash |
   | `NEXT_PUBLIC_ATTEST_TOKEN` | the approver token from above |

4. Deploy, then put the resulting origin into the service's
   `ATTEST_CORS_ORIGINS` and restart it.

CLI equivalent:

```bash
cd console && npx vercel --prod
```

**Netlify or Cloudflare Pages** work the same way: base directory `console`,
build `npm run build`, and their respective Next adapters. Both need the same
two `NEXT_PUBLIC_` variables.

### Self-hosting the console instead

`npm run build && npm run start` serves it on 3317 behind any reverse proxy.
Put it on the same origin as the service and the CORS entry becomes
unnecessary.

---

## The console's credential is public

`NEXT_PUBLIC_*` variables are compiled into the JavaScript bundle. Whatever
token you give the console is readable by anyone who opens devtools on the
deployed page. This is a property of browser apps, not a bug here, but it has
two consequences worth being deliberate about.

**Use an approver key, never the bootstrap admin key.** An admin token in the
bundle hands any visitor the ability to rewrite the thresholds that decide what
reaches a reviewer — that is, the ability to stop being asked. That is a
strictly worse outcome than having no gate, because the gate is still trusted.

**Three parts of the console need admin and will return 403 under an approver
key**: Settings (`PUT /config`), the feed controls (`/feed/start`,
`/feed/stop`), and Reset. The queue, decisions, frontier and oversight views
all work fine. For a public demo, either accept those three being read-only, or
put the whole console behind access control — Vercel password protection, an
SSO proxy, or a private deployment — and only then give it an admin token.

**Rotate the console token like any other secret.** The SSE stream carries it
as a query parameter, because `EventSource` cannot set headers, which means it
lands in access logs.

---

## Verifying a deploy

```bash
curl -sS https://your-service/health -H "Authorization: Bearer $TOKEN"
```

Expect `{"status":"ok", ...}`. Then open the console: a green stream indicator
on the decisions page means SSE is getting through the host's proxy. If the
page loads but every panel shows an error, it is almost always CORS — check
that `ATTEST_CORS_ORIGINS` matches the console origin exactly.
