# EASM Optimizer (Preview)

Re-prioritise Microsoft Defender EASM by asset instead of by raw observation.
It reads the Defender EASM data plane directly from your browser with delegated
MSAL tokens, then scores, enriches and recommends per asset — **read-only**, no
backend, nothing is ever written back to EASM.

- **File:** `blue16-easm.html`
- **Category:** External attack surface
- **Status:** Preview

---

## What it does

- Enumerates your `Microsoft.Easm/workspaces` from Azure Resource Manager so you
  never type workspace coordinates, then pulls assets and observations straight
  from the EASM data plane (one GET per 100 assets plus a per-asset observation
  POST).
- Rolls observations up **to the asset** and grades each one, so the view is
  "which assets are worth acting on" rather than a flat observation list.
- Enriches CVEs with **EPSS** (exploitation likelihood) from FIRST.org
  (`api.first.org/data/v1/epss`), which doubles the weight of anything actively
  exploited and surfaces assets in the top 10% by EPSS.
- Flags **subdomain takeover** risk from dangling DNS records on assets you own.
- Compares EASM's public footprint against your own Azure public IPs and an
  imported Defender device list to find **coverage gaps** (assets with no EDR
  sensor, "outside view" vs "inside view").
- Organises everything into tabs: **Overview, Assets, Entry Points, Findings,
  Coverage Gap, Changes, Cost Indicator**, with AI-generated prioritisation and
  remediation suggestions.

---

## Requirements

The tool signs in with MSAL and calls the EASM and ARM APIs directly — it is
**API-driven, not export-driven**, with one exception: the Coverage Gap tab
imports a Defender device list (see the input row below), because Defender's
APIs send no CORS headers and cannot be called from a browser.

A **Single-page application (SPA)** app registration is required, but note the
delegated scopes below are **all read-only and none require admin consent** —
each signed-in user just needs their own Azure role assignment.

### Microsoft Graph / API permissions (delegated, read-only, no admin consent)

| Scope / Input | Why |
|-------|-----|
| `EASM API` → `AssetResource.Read.All` | assets + observations (data plane) |
| `EASM API` → `Workspace.Read.All` | workspace metadata |
| `Azure Service Management` → `user_impersonation` | discover which EASM workspaces exist |
| `Azure Cognitive Services` → `user_impersonation` *(optional)* | only for the Azure OpenAI recommendation provider |
| Graph `openid` / `profile` / `User.Read` / `offline_access` | MSAL defaults; `offline_access` supplies the refresh token for silent renewal |
| **Import:** Defender advanced-hunting device export (JSON or CSV) | inside view for the Coverage Gap tab; the Sightline scanner's own export also works |

Azure roles (delegated tokens act as the signed-in user, so API permissions
alone grant nothing):

- **Assets** — a role on the `Microsoft.Easm/workspaces` resource; Microsoft
  documents **Contributor**.
- **Coverage gap, Azure side** — **Reader** on each subscription whose public
  IPs should be compared. A subscription you cannot read is skipped silently.

---

## How to run

1. Serve the page over **http(s)** (e.g. `blue16.nl`, GitHub Pages, or any
   static host). MSAL cannot run from `file://`.
2. Register a **Single-page application** platform on an app registration with
   this page's URL as the **SPA redirect URI** (not the *Web* platform — a Web
   registration fails the token exchange with a cross-origin redemption error).
   Add the delegated permissions above — none need admin consent.
3. Assign each user their Azure role(s): Contributor on the EASM workspace, and
   Reader on subscriptions for the coverage comparison.
4. Enter the **Application (client) ID** and **Directory (tenant) ID** (or
   `organizations`), then sign in with your Microsoft work account.
5. Pick a workspace when the account can read more than one, review the graded
   assets, and open the tabs for entry points, findings and coverage gaps.
6. On the **Coverage Gap** tab, run a Defender *Advanced hunting* export of your
   internet-facing devices, then use **Import Defender devices…** to load the
   JSON or CSV.

---

## Privacy & safety

- **Read-only by design** — nothing is ever written back to EASM.
- **No backend.** All EASM and ARM calls run from your browser with your
  delegated token; results are rendered locally and never sent anywhere by the
  tool. EPSS lookups go directly to FIRST.org.
- The EASM data plane returns `Access-Control-Allow-Origin: *`, which is what
  lets the page call it directly — verified against a live workspace.

---

## Limitations

- **No demo mode** — the tool needs a real EASM workspace and sign-in to show
  anything.
- The Defender inside view must be imported manually; Defender's APIs cannot be
  called from a browser, so an un-imported device list reads as "no sensor"
  rather than "not imported".
- Subscriptions or workspaces you lack a role on are skipped silently, which can
  look like a clean result rather than a missing one.
- EPSS enrichment is capped (first ~800 CVEs) so a very large tail is not
  scored, and the AI recommendation provider is optional.
- Preview: scoring weights and checks may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
