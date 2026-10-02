# Switchboard

Switchboard is a portfolio case study for independent creators and developers who use separate Google, GitHub and Discord accounts. One page shows which profile was authorized, whether its grant still works, and when the profile was last checked.

It demonstrates OAuth 2.0 authorization code flows and a backend-for-frontend (BFF). It does not claim measured time savings, real users, conversion results, revenue or production readiness.

## Product and scope

Connect a provider from its own card. The provider redirects back to Switchboard, the backend exchanges the one-time code, then reads the profile using the provider API. The page shows the returned name, handle, avatar when available, grant status and last successful profile check. **Check grant** makes another read-only profile request. If the grant has expired or been revoked, Switchboard marks it for reconnection. **Remove** deletes the local connection and saved tokens; it does not revoke consent at the provider.

Google, GitHub and Discord are independent connections. Connecting Google does not create a GitHub or Discord connection. Every visitor authorizes their own provider accounts. There is no separate Switchboard user login: an opaque browser cookie scopes each visitor's workspace. Demo mode has no fabricated connected users or profiles.

| Provider | Flow and requested access | Profile data shown |
| --- | --- | --- |
| Google | Authorization Code, PKCE S256; `openid email profile` | Name, verified email when returned, avatar |
| GitHub | Authorization Code, PKCE S256; `offline_access` | Name or login, avatar, profile link |
| Discord | Authorization Code; `identify` | Display name or username, avatar, Discord profile link |

Discord's Web OAuth2 reference does not document PKCE parameters for its authorization-code flow. Switchboard sends single-use `state` and performs the code exchange on the backend without inventing PKCE support. It requests only `identify`; it does not request email, guilds, bot access or message permissions. Profile fields are limited to what each provider returns. The app does not display repositories, server lists, YouTube data or analytics.

## OAuth and hosting architecture

The Angular app is a static Cloudflare Pages project. A narrowly routed Pages Function proxies only `/api/*` to the ASP.NET Core backend on Render. The browser calls the Pages origin for both the UI and API, so the opaque `HttpOnly` cookie stays first-party even though the API process runs on Render.

```mermaid
sequenceDiagram
    actor Visitor
    participant Browser as Browser on Pages origin
    participant Pages as Cloudflare Pages
    participant Proxy as Pages Function /api/*
    participant API as ASP.NET Core on Render
    participant Provider as Google / GitHub / Discord
    participant Store as Encrypted workspace files

    Browser->>Pages: Load Angular app
    Browser->>Proxy: GET /api/session
    Proxy->>API: Forward request and opaque cookie
    API-->>Proxy: CSRF token and HttpOnly cookie
    Proxy-->>Browser: Same-origin API response and cookie
    Visitor->>Browser: Choose Connect
    Browser->>Proxy: POST /api/connections/{provider}/start + CSRF
    Proxy->>API: Forward cookie, form and CSRF header
    API->>Store: Save provider-bound, one-use state and PKCE verifier
    API-->>Browser: 302 to provider authorization page
    Browser->>Provider: Approve profile access
    Provider-->>Proxy: GET Pages-origin /api/oauth/{provider}/callback?code&state
    Proxy->>API: Forward callback and same Pages cookie
    API->>Store: Verify and consume state
    API->>Provider: Exchange code and fetch profile server-side
    Provider-->>API: Token response and profile
    API->>Store: Protect token and save normalized connection
    API-->>Browser: Redirect to Pages app with safe status only
    Browser->>Proxy: GET /api/connections
    Proxy->>API: Forward same-origin cookie
    API-->>Browser: Profile and safe grant metadata; no tokens
```

The API proxy uses a fixed `API_ORIGIN` environment variable, forwards the browser cookie and request body, keeps redirects manual for OAuth, preserves `Set-Cookie`, and rejects oversized bodies. It does not accept an upstream host from a request parameter. `_routes.json` limits Function execution to API paths; static Angular assets bypass the Function.

OAuth state is random, provider-bound, single-use and expires after ten minutes. Google and GitHub use PKCE S256. Callbacks accept only one `state` and `code`; cancellation and provider errors are reduced to safe categories. Tokens stay in ASP.NET Core and are encrypted at rest with Data Protection. The browser receives an opaque `HttpOnly`, `Secure`, `SameSite=Lax` cookie on Pages. State-changing endpoints require the in-memory CSRF token. OAuth codes, state and tokens are not logged or returned by public API responses.

The details panel shows protocol data useful for inspection: callback URL, requested and granted scopes, token expiry, refresh-token availability and provider endpoints. It never displays token values.

## Product hypotheses

**Audience:** independent creators and developers who use more than one service account.

**Job:** confirm which provider profile is connected and spot a grant that needs authorization again without opening each provider's account settings.

| Metric to validate | Definition | Initial target hypothesis |
| --- | --- | --- |
| Successful first connection rate | First OAuth starts ending in a usable profile ÷ first OAuth starts | At least 85% |
| Time to first connected account | Median seconds from workspace creation to first usable provider profile | At most 60 seconds |
| Fresh connected profiles | Connected profiles fetched successfully in the last seven days ÷ all connected profiles | At least 90% |

These are targets, not measurements. The app collects no analytics, so it cannot currently calculate them. A future measurement pass should decide what to collect and how long to retain it before showing numbers to users.

**Monetization hypothesis:** if creators repeatedly use a combined account view, test whether multiple workspaces or shared team workspaces are worth paying for. There is no billing implementation or willingness-to-pay evidence.

## Stack

- Angular 20, standalone components, signals, HttpClient, Jasmine/Karma.
- Cloudflare Pages for static assets and a small API proxy Function.
- ASP.NET Core 8 BFF and provider API calls on Render.
- Encrypted per-browser workspace files and ASP.NET Core Data Protection.
- Docker for the Render backend; GitHub Actions for frontend and backend checks.

## Run locally

Requirements: .NET 8 SDK, Node.js 22 or newer, npm and Python 3.

Start the backend from this repository root:

```sh
dotnet run --urls http://localhost:5223
```

In another terminal:

```sh
cd frontend
npm ci
npm start -- --host 127.0.0.1 --port 4300
```

Open `http://localhost:4300`. With no configured provider clients, the interface clearly shows demo mode and unconnected cards. No synthetic connected profile is presented as real.

### Enable live provider connections locally

Create the provider OAuth clients in their developer consoles and register these exact callbacks:

```text
Google:  http://localhost:5223/api/oauth/google/callback
GitHub:  http://localhost:5223/api/oauth/github/callback
Discord: http://localhost:5223/api/oauth/discord/callback
```

From this repository root, run `python3 tools/configure_local_oauth.py`. It prompts for Google and optional GitHub/Discord credentials and stores them in .NET User Secrets; secret input is hidden. Restart the backend. Do not paste credentials into Angular, tracked settings, logs or chat.

Google profile, GitHub profile and Discord profile are separate authorization grants. No YouTube integration is included.

## Configuration and secrets

`appsettings.example.json` has placeholders. `appsettings.json` contains local defaults only. Local client IDs and secrets belong in .NET User Secrets. Hosted secrets belong in Render's environment-secret settings:

```text
OAuth__Google__ClientId
OAuth__Google__ClientSecret
OAuth__Github__ClientId
OAuth__Github__ClientSecret
OAuth__Discord__ClientId
OAuth__Discord__ClientSecret
```

The browser-facing API origin is configured as `API_ORIGIN` in Cloudflare Pages. It must be the absolute HTTPS origin of the Render backend, without a path. Render's `App__PublicOrigin` and `App__FrontendOrigin` must both be the canonical Pages origin, such as `https://switchboard.pages.dev`. These origins determine provider callback and post-callback redirect URLs.

## Temporary public deployment: Cloudflare Pages + Render

The repository is arranged for two free-tier services. Use the default `pages.dev` host first; a custom domain can be added later.

### 1. Deploy Angular on Cloudflare Pages

In Cloudflare Dashboard, create a Pages project and connect this GitHub repository. Use:

| Setting | Value |
| --- | --- |
| Production branch | `main` |
| Root directory | `frontend` |
| Build command | `npm run build` |
| Build output directory | `dist/Switchboard/browser` |

Cloudflare's Angular guide uses the Angular build output directory; this app's current Angular 20 project emits `dist/Switchboard/browser`. The first static build can complete before the API is configured.

### 2. Deploy the API on Render

In Render, choose **New → Blueprint**, connect the same repository, and apply the root `render.yaml`. When Render asks for `App__PublicOrigin` and `App__FrontendOrigin`, enter the exact Pages origin from step 1. Enter provider IDs and secrets in Render's secret prompts; never add these values to Git.

After deployment, copy the backend's HTTPS `onrender.com` origin. In Cloudflare Pages **Settings → Variables and Secrets**, set the production variable:

```text
API_ORIGIN=https://<your-render-service>.onrender.com
```

Redeploy the Pages project after saving the variable.

### 3. Register provider callbacks

Use the Pages origin—not the Render API origin—because callbacks pass through the same-origin Pages Function:

```text
https://<your-pages-project>.pages.dev/api/oauth/google/callback
https://<your-pages-project>.pages.dev/api/oauth/github/callback
https://<your-pages-project>.pages.dev/api/oauth/discord/callback
```

Register each URL in its matching provider console. Set the provider client IDs and secrets in the Render service environment. For Google, the current authorization request uses only the basic `openid email profile` identity scopes; check the OAuth consent screen's publishing status and test-user rules in Google Cloud before inviting visitors.

OAuth from Cloudflare preview deployment URLs is not configured; test connections on the stable production `pages.dev` origin. When adding a custom Pages domain later, update both Render origin variables, each provider callback URL, and the Pages OAuth homepage/branding configuration as applicable.

### Free-tier limits

Cloudflare static asset requests are free and unlimited, while Pages Function calls count against the Workers request quota. Render's free web service can spin down after inactivity and has an ephemeral filesystem. This preview stores workspaces and Data Protection keys under `/tmp`, so a restart, spin-down or redeploy can lose connections and sessions; visitors may need to reconnect. This setup is for a public trial, not durable production data. A longer-lived service needs persistent storage and a protected Data Protection key ring.

## Checks

From repository root:

```sh
python3 -m unittest discover -s tools -p 'test_*.py'
dotnet test Tests/Oauth2_backend.Tests/Oauth2_backend.Tests.csproj --configuration Release
cd frontend
npm ci
npm run test:proxy
npm test -- --watch=false --browsers=ChromeHeadless
npm run build -- --configuration production
```

Provider tests use fake HTTP handlers and never contact providers. Coverage includes OAuth state, replay and expiry; provider errors and scopes; PKCE; CSRF; workspace isolation and encryption; token non-disclosure; refresh; profile normalization; Pages proxy cookies, redirects, fixed upstream, CSRF forwarding and request-size limits.

## Engineering choices and limits

- Keep provider connection separate from application login; this version has no Switchboard user account, password or recovery flow.
- Keep provider tokens in the BFF and expose only normalized profile fields plus safe lifecycle metadata.
- Request minimal profile access. Discord only needs `identify` for `/users/@me`.
- Use the provider-supported authorization-code behavior; do not invent PKCE support for Discord.
- Keep one backend instance and file-based encrypted persistence for a simple demonstrator. This does not provide durable storage, multi-instance coordination, cross-device recovery, background checks or billing.
- Use a Pages proxy because direct cross-site browser calls would complicate the BFF cookie. The proxy lets the browser stay on the Pages origin while the backend remains a separate Render service.

Switchboard is an OAuth case study and temporary public demo. It is not described as production-ready.
