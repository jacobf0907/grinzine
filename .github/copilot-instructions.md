## Quick context

This repo hosts the GRIN website and its API. The frontend is static HTML/CSS/JS under `docs/` (served as the public site). The backend is a Fastify-based API in the repo root (`fastify-server.js`, `fastify-api.js`, `fastify-auth.js`) that handles auth, Stripe checkout/webhooks, and Prisma DB access. Prisma models live in `prisma/schema.prisma` and there is a small seed script at `prisma/seed.js`.

## High-level architecture (why and how)

- Frontend: `docs/` — static pages (index.html, issues.html, login.html, etc.). Frontend calls the API at `http://localhost:4242` in dev or `https://api.grinzine.com` in prod (see `docs/index.html` API_BASE_URL logic).
- API / Server: `fastify-server.js` is the main entry. It registers security, cookie handling, CSRF, static file serving and the Stripe webhook. Plugins exist for api (`fastify-api.js`) and auth (`fastify-auth.js`) but some handlers (notably the Stripe webhook) were intentionally left on the main server to ensure raw body access.
- Auth: JWT stored in an httpOnly cookie named `token`. Auth helpers live in `fastify-auth.js`. The cookie plugin is registered globally in `fastify-server.js` with `encapsulate: false` — do not duplicate or re-register it inside plugins.
- Payments: Stripe checkout creation is protected and uses Stripe webhooks to record purchases into the database. The webhook requires the raw request body and signature verification — see `fastify-server.js` content-type parser change: `addContentTypeParser('application/json', { parseAs: 'buffer' }, ...)` and the `/webhook` route.
- Database: Prisma is used (models in `prisma/schema.prisma`). The repo provides `prisma/seed.js` that uses `ISSUES` from the repo to seed `Issue` rows.

## Key developer workflows

- Start server: `npm run start` (runs `node fastify-server.js`).
- Seed DB: `npm run seed` (runs `node prisma/seed.js`). The schema expects a `DATABASE_URL` env var (see `prisma/schema.prisma` datasource).
- Dev reloads: `nodemon` is a devDependency — during development you can use `npx nodemon fastify-server.js` if you want auto-reload.

## Project-specific patterns & gotchas (do not change lightly)

- Cookie & plugin encapsulation: `fastifyCookie` is registered globally with `encapsulate: false`. Many auth flows expect cookies to be available in plugins. If you refactor plugin registration or change encapsulation, verify `request.cookies` inside plugins (see extensive logging in `fastify-auth.js` and `fastify-server.js`).
- Stripe webhook raw body: The webhook uses Stripe's signature verification. Keep the `addContentTypeParser('application/json', { parseAs: 'buffer' }, ...)` approach or ensure the webhook receives the raw buffer — otherwise signature verification will fail.
- ISSUES mapping: Price IDs -> issues come from `issues.js` and are mapped both in `fastify-api.js` and `fastify-server.js`. Keep that mapping consistent when adding/removing issues.
- Frontend API_HOST logic: Frontend toggles API host based on hostname (see `docs/index.html` — API_BASE_URL selection). When testing locally, use `http://localhost:4242`.

## Important files to inspect (examples)

- `fastify-server.js` — main entry: cookie registration, CSP/helmet settings, CORS origins, raw JSON buffer parser, webhook and protected routes.
- `fastify-auth.js` — auth routes, `requireAuth` preHandler and cookie-to-JWT handling; uses Prisma via `./db`.
- `fastify-api.js` — public API plugin (purchase status, subscribe endpoint, etc.).
- `issues.js` — canonical list of issues, price IDs and pdfPath used by seed & Stripe handling.
- `prisma/schema.prisma` & `prisma/seed.js` — DB schema and seeding logic.
- `docs/` — static frontend; see `index.html` and `scripts.js` for integration examples (logout, fetch to `/auth/my-library`, etc.).

## Environment variables (observed in code)

- STRIPE_MODE (live/test)
- STRIPE_SECRET_KEY_LIVE, STRIPE_SECRET_KEY_TEST
- STRIPE_WEBHOOK_SECRET_LIVE, STRIPE_WEBHOOK_SECRET_TEST
- JWT_SECRET
- GMAIL_USER, GMAIL_PASS (used to send reset emails)
- ALLOWED_ORIGIN (frontend base URL in some flows)
- DATABASE_URL (Prisma datasource)
- PORT (defaults to 4242)

If any of these are missing the server logs a warning or may fail; check `fastify-server.js` early env checks.

## Small checklist for changes that touch auth/webhooks

- If adding a webhook route: ensure the raw body parser is preserved or the handler uses a raw-body approach.
- If moving routes into plugins: verify cookie availability and that `fastify-cookie` is registered globally (encapsulate:false) before the plugin registers.
- If changing the DB schema: update `prisma/schema.prisma`, migrate appropriately and update `prisma/seed.js` or the seed usage.

## How to run quick smoke tests locally

1. Ensure env vars (at least `JWT_SECRET`, `DATABASE_URL`, Stripe keys and webhook secret for full checkout flow) or stub them for smoke testing.
2. Seed DB: `npm run seed`.
3. Start server: `npm run start` (or `npx nodemon fastify-server.js` for reloads).
4. Visit `docs/index.html` served statically (you can open the file directly) and test API calls against `http://localhost:4242`.

## If you need more context / next steps

- I based these notes on `fastify-server.js`, `fastify-auth.js`, `fastify-api.js`, `prisma/schema.prisma`, `prisma/seed.js`, `package.json` and `docs/index.html`. If you'd like, I can:
  - Expand example snippets (e.g., exact code to preserve raw webhook parsing when refactoring),
  - Add a small CONTRIBUTING.md with dev env examples (.env.example), or
  - Wire a `dev` script (nodemon) into `package.json`.

Please review and tell me if any sections are unclear or missing detail to iterate.
