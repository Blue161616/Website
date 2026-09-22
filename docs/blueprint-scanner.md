# Entra Blueprint Security Posture (Preview)

Inventory and risk-band every **agent identity blueprint** in your Microsoft
Entra tenant — the object that holds the credential and can mint and impersonate
the agent identities created from it — and see its blast radius. It runs
entirely in your browser against Microsoft Graph — **read-only by default**, no
backend, no data leaves the page.

- **File:** `blueprint-scanner.html`
- **Identity type / Category:** Agent (agent identity blueprints)
- **Status:** Preview

---

## What it does

Enumerates the agent identity blueprints present in the tenant — including
**externally-owned** ones published by another tenant — and places each in one
of three risk bands: **Critical**, **High risk** or **Healthy**. The blueprint
is treated as the security boundary, because it holds the credential and controls
the inheritance conduit for every agent it mints. Signals scored include:

- **Tenancy / origin** — home-authored vs an externally-owned blueprint whose
  publisher holds the credential and can create agent identities in your tenant.
- **Client credentials** — secret vs certificate vs federated identity
  credential (FIC). A copyable client secret is the weakest; a secret retained
  alongside a FIC, multiple/accumulated secrets, and expired credentials are all
  flagged.
- **Blast radius** — how many agent identities inherit the blueprint, plus
  orphans (a live credential with zero agents) and dormancy (no agent sign-in for
  30+ days while a live credential remains — the Critical shape).
- **Declared permissions, app roles and consent** — delegated and application
  consent on the blueprint principal, with permission-scope GUIDs resolved to
  names.
- **Risk state and Conditional Access coverage** — for workload identities, when
  the licence and optional scopes are present.

The table shows only exceptions (a blank cell is the safe default), supports
filtering and facets, a per-blueprint blast-radius view, a JWT token decoder, and
**Export CSV / JSON**.

---

## Requirements

- A **Single-page application (SPA)** app registration (not a *Web* platform — a
  Web registration fails the token exchange with a cross-origin redemption
  error).
- The page's own URL registered as a **SPA redirect URI** (https, or http on
  loopback only — not `file://` and not a machine name/IP over http).
- Admin consent for the scopes below, and a signed-in account with read access.
  **Global Reader** covers everything the scan reads and grants no write
  anywhere; **deleting** additionally needs the **Agent ID Administrator** role.
- Agent ID APIs are newest on the **beta** Graph endpoint; switch to it if `v1.0`
  returns errors.

### Microsoft Graph permissions (delegated, admin consent)

**Required — the scan cannot start without these:**

| Scope | Why |
|-------|-----|
| `AgentIdentityBlueprint.Read.All` | blueprints in this tenant |
| `AgentIdentity.Read.All` | the agent identities created from them |
| `AgentIdentityBlueprintPrincipal.Read.All` | blueprints present in the tenant, including externally-owned ones |
| `Application.Read.All` | resolves permission-scope GUIDs to names, and reads app-role assignments |
| `DelegatedPermissionGrant.Read.All` | delegated consent on the blueprint principal |
| `CrossTenantInformation.ReadBasic.All` | resolves an external blueprint's owner tenant to its org name and domain |
| `User.Read` | sign-in |

**Optional — each degrades gracefully; an absent one is reported as *not
assessed*:**

| Scope | Why |
|-------|-----|
| `AuditLog.Read.All` | per-agent sign-in and dormancy |
| `IdentityRiskyAgent.Read.All` | risk state (falls back to `IdentityRiskyServicePrincipal.Read.All`) |
| `Policy.Read.All` | Conditional Access coverage |

> Risk state and Conditional Access for workload identities both need **Workload
> ID Premium**; without the licence the scopes are granted but return nothing,
> which the page reports as hidden rather than as clean.

**Delete — requested only when you delete, never at sign-in:**

| Scope | Why |
|-------|-----|
| `AgentIdentityBlueprint.DeleteRestore.All` | delete a blueprint — **cascades** to the agents created from it |
| `AgentIdentity.DeleteRestore.All` | delete a single agent identity |

> Both are `DeleteRestore` scopes, which need only the **Agent ID
> Administrator** role (not Cloud Application Administrator). An auditor can run
> the whole scan without holding delete rights.

---

## How to run

1. Open the page over https (or http on localhost). `file://`, a machine name or
   an IP over http will not work.
2. Register the page URL as a **SPA** redirect URI on an app registration, and
   grant admin consent for the seven required scopes.
3. Enter the **Application (client) ID** and **Directory (tenant) ID or domain**
   (`organizations` if unsure), pick the Graph API version (try **beta** if
   `v1.0` errors), and connect.
4. Load / refresh blueprints, review the risk-banded table and per-blueprint
   blast radius, and export to CSV or JSON. Deleting a blueprint or agent
   requests its delete scope at that moment and names the exact blast radius.

### Try it without a tenant — Demo mode

Append `?demo=1` to the URL (or use the demo link in the page) to load a
**synthetic tenant**: no sign-in, nothing fetched from Graph. Every number is
generated and scored by exactly the same rules a real scan uses.

---

## Privacy & safety

- **Read-only by default.** The only write actions are the two `DeleteRestore`
  operations, and their scopes are requested only when you delete — a session
  that deletes nothing never asks for them.
- **No backend.** All Graph calls run from your browser with your delegated
  token; results are rendered locally and never sent anywhere by the tool.
- Least privilege — deletes need only Agent ID Administrator, deliberately
  avoiding the broader Cloud Application Administrator that a generic
  `/applications` delete would have required.

---

## Limitations

- Risk state and Conditional Access coverage need a **Workload ID Premium**
  licence; without it those columns are hidden rather than shown clean.
- Externally-owned blueprints expose the publisher's credential and inheritance
  conduit only partially — the conduit itself returns 404 to you by design.
- Agent ID APIs are still maturing; some data is only on the **beta** endpoint.
- Preview: scoring, risk bands and checks may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
