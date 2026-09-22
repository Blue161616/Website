# Copilot Studio Agent Security Posture (Preview)

Scan the Copilot Studio agents in your Power Platform environments and surface the
security signals that decide how dangerous an agent is if it were abused —
authentication mode, connector credentials, egress paths, sharing, AI model and
data-residency. It runs entirely in your browser against the **Dataverse Web API**
with your delegated access — **read-only**, no backend, no data leaves the page.

- **File:** `Copilot-Studio-Security-Auditor.html`
- **Category:** Copilot Studio
- **Status:** Preview

---

## What it does

Reads the `bot` and `botcomponent` tables of each Dataverse environment you can
reach and raises findings per agent, then correlates the dangerous combinations:

- **Authentication** — agents with *No authentication* or *Integrated* only.
- **Maker credentials** — connectors that run in the maker (standing-credential)
  auth context (`connectionProperties.mode=maker`).
- **Egress paths** — `HttpRequestAction` usage, cleartext HTTP, non-standard
  ports, and Office 365 / Outlook *SendEmail* with external or AI-controlled
  (dynamic) recipients.
- **MCP tool surface** — `InvokeExternalAgentTaskAction` usage, naming the MCP
  server(s) where identifiable.
- **Sharing** — who each agent is shared with and with what rights (team-wide,
  re-share, write, reassign, delete), via `RetrieveSharedPrincipalsAndAccess`.
- **Orphaned / multi-tenant** — agents whose Dataverse owner is disabled, and
  configurations indicating multi-tenant / org-wide access.
- **AI model & EU Data Boundary** — the model each agent runs (`modelNameHint`),
  flagging models hosted outside the EU Data Boundary and agents grounded with
  Bing web search (data leaves the Azure compliance boundary).
- **Agent capabilities** — an inventory line per agent for Tools, Knowledge and
  Memory (Memory is tri-state: on / off / not stated, never guessed).
- **Risk correlation** — escalates combinations such as an anonymous agent with a
  data-egress path, or an MCP tool running on maker credentials, to Critical.

Results render as a risk matrix, KPI tiles, a filterable findings table, and a
Leaflet map of tenant data residency.

---

## Requirements

- A **Single-page application (SPA)** app registration (not a *Web* platform — a
  Web registration fails the token exchange with a cross-origin redemption error).
- The page's own URL registered as a **SPA redirect URI**.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- A **Dataverse security role** in each environment you want scanned. Permissions
  alone do not grant data access, and an environment you cannot read is skipped.

The page ships pre-filled with Blue16's published multi-tenant app
(`96e9b5f4-e974-4355-ae9f-4487099ef210`); a single-tenant registration must enter
its own Client ID and pin its home tenant, otherwise sign-in fails with
`AADSTS650059`.

### API permissions (delegated)

| Scope / API | Why |
|-------|-----|
| `User.Read` (Microsoft Graph) | sign-in only |
| `user_impersonation` (Dynamics CRM, `00000007-0000-0000-c000-000000000000`) | **required** — reads agents from Dataverse and discovers environments; without it every environment fails with `AADSTS650057` |

Then **Grant admin consent**. Environment discovery uses the Global Discovery
Service (`globaldisco.crm.dynamics.com`); Dataverse tokens are acquired per
environment URL (`<org>/.default`).

---

## How to run

1. Serve the page over http(s) (e.g. via `blue16.nl`, GitHub Pages, or any static
   host). `file://` will not work.
2. Register the page URL as a **SPA** redirect URI on an app registration with the
   Dynamics CRM `user_impersonation` permission, and grant admin consent.
3. Enter the **Client ID** and **tenant** (`organizations` for the multi-tenant
   app), then either paste **environment URL(s)** or click **Discover my
   environments**.
4. Optionally toggle *Scan agent components* (Maker / HTTP / MCP / Send Mail) and
   *Resolve sharing* (slower — one call per agent), then **Sign in & scan**.
5. Review the risk matrix and findings; the scan summary spells out whether a
   "0 findings" result is a clean tenant, an empty environment, or a missing role.

---

## Privacy & safety

- **Read-only.** The tool only reads Dataverse tables and sharing; it never writes.
- **No backend.** All calls run from your browser with your delegated token;
  results are rendered locally and never sent anywhere by the tool.
- Coverage is limited to environments where your account holds a Dataverse
  security role — permissions alone don't grant data access.

---

## Limitations

- Coverage stops at environments where you have a Dataverse security role; others
  are skipped silently.
- The **Send Mail**, **Maker**, **MCP-server name** and **multi-tenant** signals
  are heuristic pattern matches over agent/component JSON, whose field names are
  undocumented and may change.
- The data-residency map shows where the agent *environment* is hosted; the AI
  **models** agents invoke may process prompts outside the EU Data Boundary
  regardless — verify model residency separately.
- No demo mode: the tool requires a real sign-in and at least one environment.
- Preview: scoring and checks may change, and some signals derive from Preview
  features whose schema may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
