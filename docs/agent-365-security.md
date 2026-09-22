# Agent 365 Security Overview (Preview)

A live security overview of the AI agents in your Microsoft tenant, organised the
way Microsoft splits the problem — **Entra** (identity & access), **Defender**
(threat protection / runtime) and **Purview** (data governance). It discovers
modern and classic agents, scores them, and reports findings with remediation.
It runs entirely in your browser against Microsoft Graph — **read-only**, no
backend, delegated token only.

- **File:** `agent-365-security.html`
- **Category:** Agent 365
- **Status:** Preview

---

## What it does

Signs in to your tenant, enumerates agent identities and surfaces their posture
across the three Microsoft security engines:

- **Overview** — a score card summarising the agent estate.
- **Microsoft Entra** — identity & access findings and remediation (service
  principals, privileged directory roles held by agents, credential/tenancy
  hygiene, Conditional Access for agents).
- **Microsoft Defender** — runtime threat-protection findings from the Defender
  **AgentsInfo** advanced-hunting table, plus XDR incidents implicating agents.
- **Microsoft Purview** — data-governance findings, including the sensitivity-
  label taxonomy and default label.
- **Agents** — the discovered inventory of modern agent identities and **local /
  classic** agents (classic agents are covered via service principals by tag).
- **Models** — the underlying LLMs agents run on, read live from the Defender
  `AgentsInfo` **Model** column, with a data-residency / GDPR flag for US-hosted
  models.
- **Tools & MCP** — each agent's action surface (tools, MCP servers, connectors)
  read from `AgentsInfo`.

Absent optional signals are reported as *not assessed* rather than as a clean
result. The Agent 365 registry's own total and what Defender sees rarely match
exactly (different collectors, different scopes).

---

## Requirements

- A **Single-page application (SPA)** app registration in the tenant you want to
  assess (not a *Web* platform — a Web registration fails the token exchange with
  a cross-origin redemption error).
- The page's own URL registered as a **SPA redirect URI**.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- An account that can grant (or has been granted) admin consent for the scopes
  below, and a directory role such as **Global Reader** for the tenant-wide reads.

### Microsoft Graph permissions (delegated, read-only, admin consent)

**Required — the scan cannot start without these:**

| Scope | Why |
|-------|-----|
| `AgentIdentity.Read.All` | modern agent identities |
| `Application.Read.All` | service principals — also covers **classic** agents by tag |
| `Directory.Read.All` | directory objects, licences |
| `User.Read` | sign-in |

**Optional — each degrades gracefully; an absent one is reported as *not
assessed*:**

| Scope | Why |
|-------|-----|
| `ThreatHunting.Read.All` | Defender **AgentsInfo** hunting — full discovered inventory, models & tools |
| `IdentityRiskyAgent.Read.All` | ID Protection for Agents — `riskyAgents` + `agentRiskDetections` (P2) |
| `Policy.Read.All` | Conditional Access for Agents coverage |
| `RoleManagement.Read.All` | privileged directory roles held by agents |
| `AuditLog.Read.All` | agent sign-in dormancy |
| `SecurityIncident.Read.All` | Defender XDR incidents implicating agents |
| `InformationProtectionPolicy.Read` | Purview sensitivity-label taxonomy + default label |

---

## How to run

1. Open the page over http(s) (e.g. via `blue16.nl`, GitHub Pages, or any static
   host). `file://` will not work.
2. Register the page URL as a **SPA** redirect URI on an app registration, and
   grant admin consent for at least the four required scopes (add the optional
   ones to light up Defender, Purview and risk signals).
3. Enter the **Application (client) ID** and, under *App registration setup*, the
   **Directory (tenant) ID or domain** (`organizations` if unsure) and the Graph
   API version (`v1.0` is GA for `agentIdentity`; `beta` exposes extra
   properties).
4. Sign in, then browse the Overview, Entra / Defender / Purview engines, Agents,
   Models and Tools & MCP views.

The page reads its own redirect URI and displays it for you to register; the
signed-in identity shows in the header.

---

## Privacy & safety

- **Read-only.** Every listed scope is a `*.Read*` delegated permission; nothing
  the tool requests writes to the tenant.
- **No backend.** All Graph and advanced-hunting calls run from your browser with
  your delegated token (cached in `sessionStorage`); results are rendered locally
  and never sent anywhere by the tool.
- Client ID / tenant ID / Graph version are remembered in `localStorage` for
  convenience only.

---

## Limitations

- Preview: findings, scoring and checks may change.
- Defender-sourced views (full inventory, Models, Tools & MCP) and risk/CA/label
  signals depend on the corresponding optional scopes and licences (e.g. ID
  Protection for Agents needs P2); without them those areas read *not assessed*.
- Discovery totals from the Agent 365 registry and from Defender will not match
  exactly — they are different collectors with different scopes.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
