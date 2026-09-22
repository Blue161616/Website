# Classic → Modern Agent Migrator (Preview)

Inventory the classic agents in your Microsoft Entra tenant — Copilot Studio,
Foundry and pro-code service-principal agents — and, for the pro-code ones, copy
each into a **modern Entra Agent ID** blueprint identity. Because in-place
migration isn't supported, each classic agent is recreated as a new agent identity
(named "*&lt;original name&gt; (new)*" by default). It runs entirely in your browser
using your own delegated access.

- **File:** `classic-to-modern-agent-migrator.html`
- **Category:** Migration
- **Status:** Preview

---

## What it does

Three tabs, one journey (discover → classify → advise → verify):

- **Pro-code migration** *(read + write)* — enumerates classic agents that exist
  as service principals via Microsoft Graph, classifies each (modern already
  copied / classic to copy / disable-retire), and can **create** the modern
  blueprint, its principal and the copied agent identities. This is the only tab
  that writes.
- **Copilot Studio inventory** *(read-only)* — reads full agent config from the
  Dataverse `bot` and `botcomponent` tables per environment.
- **Foundry agents** *(read-only)* — reads agent config from Azure AI Foundry, with
  project auto-discovery via ARM.

KPI tiles, a migration-status donut and a filterable, expandable agent table show
what is classic, what is already modern, and what to migrate or retire.

---

## Requirements

- A **Single-page application (SPA)** app registration. The page ships pre-filled
  with the published app `a24693b7-6dd5-49b1-9748-666c5bdb5612`
  (**single-tenant**, home tenant `82d2b6a0-7115-44c1-a787-4e01392b852a`); use your
  own registration and tenant if you run one.
- The page's own URL registered as a **SPA redirect URI**, served over http(s) —
  MSAL cannot run from `file://`.
- **Directory role** — the signed-in user needs **Agent ID Developer** or **Agent
  ID Administrator** to create blueprints & agent identities (blueprint *owners*
  can create agent identities without a role).

### Microsoft Graph permissions (delegated)

Requested at sign-in; these cover the classic inventory on the pro-code tab.

| Scope | Why |
|-------|-----|
| `User.Read` | identify signed-in user (default sponsor/owner) |
| `Application.Read.All` | enumerate classic agent service principals & app registrations |
| `Directory.Read.All` | owners, resolve sponsor/owner user IDs |
| `AuditLog.Read.All` | *optional* — sign-in activity for last-used data |

### Write permissions — pro-code migration only

Requested on demand when you run a migration (leave them out for audit-only, and
if you only run the read-only tabs). Blueprint/agent creation goes to Microsoft
Graph's `agentIdentityBlueprint` / `agentIdentity` endpoints.

| Scope | Why |
|-------|-----|
| `AgentIdentityBlueprint.Create` | create an agent identity blueprint |
| `AgentIdentityBlueprintPrincipal.Create` | create the blueprint's principal |
| `AgentIdentity.Create.All` | create modern agent identities from a blueprint |
| `AgentIdentity.ReadWrite.All` | read existing modern agents / manage copies |

### Data-plane permissions — per tab

| Tab | Auth model |
|-----|-----|
| Copilot Studio | `user_impersonation` on **Dynamics CRM** (`00000007-0000-0000-c000-000000000000`), consented on first use; reads `bot`/`botcomponent`. Needs a Dataverse security role per environment. |
| Foundry (discovery) | `user_impersonation` on **Windows Azure Service Management API** (`797f4846-ba00-4fd7-ba43-dac1f8f63013`, audience `management.azure.com`); needs Azure RBAC **Reader** on the subscriptions. |
| Foundry (agent reads) | **Pasted token**, audience `https://ai.azure.com` — no app-registration permission mints it, so the tab takes a token from `Get-AzAccessToken -ResourceUrl "https://ai.azure.com"` (or `az account get-access-token --scope https://ai.azure.com/.default`). Needs Azure RBAC **Foundry User** per project; token expires in ~60–90 min. |

Add the scopes in your app registration and **Grant admin consent** once,
tenant-wide (include the create scopes only for pro-code migration); the three
data-plane APIs are consented the same way or per-user on first use of that tab.

---

## How to run

1. Serve the page over http(s), register its URL as a **SPA** redirect URI, add
   the scopes you need and grant admin consent.
2. Enter the **Client ID** and **tenant**, then **Sign in with Microsoft**.
3. Pick a tab. **Copilot Studio** and **Foundry** are read-only inventories;
   **Pro-code migration** discovers classic service-principal agents and can copy
   selected ones into modern Agent ID blueprint identities.
4. For the pro-code write path, select the agents to copy and confirm — the tool
   creates a blueprint, its principal, and one new agent identity per classic
   agent. This grants and uses the create scopes at that point.

---

## Privacy & safety

- **Read-only except pro-code migration.** The Copilot Studio and Foundry tabs
  only read; the write scopes are requested on demand and only the pro-code tab
  creates blueprints and agent identities.
- **Writes are additive, not in-place** — each classic agent is *copied* to a new
  identity; the original service principal is left as-is.
- **No backend.** All calls run from your browser with your delegated (or pasted)
  token; nothing is sent anywhere by the tool.

---

## Limitations

- In-place migration is not supported by the platform, so migration always creates
  a new agent identity rather than converting the classic one.
- Copilot Studio coverage is limited to environments where you hold a Dataverse
  security role.
- The Foundry agent reads depend on a manually pasted `ai.azure.com` token that
  cannot be minted by the app registration and expires within ~60–90 minutes.
- Pro-code creation requires the Agent ID directory role (or blueprint ownership)
  and the create scopes; without them the tool stays an inventory.
- No demo mode: the tool requires a real Entra sign-in.
- Preview: the Agent ID Blueprint platform and its Graph endpoints may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
