# WorkIQ × Agent 365 Security (Preview)

Explains what Microsoft **Work IQ** is — the organizational knowledge & reasoning
layer over Microsoft 365 — and then measures its real security exposure in your
tenant along four stages: **posture → exposure → risk → exploitation**. Because
agents reach work data **on the signed-in user's behalf (OBO)**, their true reach
is the operating user's own access — a surface application-permission scans
cannot see. It runs entirely in your browser against Microsoft Graph, **read-only**,
using your own app registration.

- **File:** `agent-365-workiq.html`
- **Category:** Agent 365
- **Status:** Preview

---

## What it does

After sign-in it scans agent identities and walks four stages on your tenant's
data:

- **1 · Posture** — which agents are wired to Work IQ, the M365 domains they
  touch, Work-IQ vs external tooling, ownership and Conditional-Access hygiene.
- **2 · Exposure** — the OBO reach map (agents × M365 domains) and how many
  high-sensitivity labels are reachable on a user's behalf. This surface is
  invisible to an application-permission scan.
- **3 · Risk** — agents that read work data **and** hold an egress/web tool,
  without DLP or Conditional Access to contain them. Containment depends on how
  the agent authenticates: OBO / Copilot Studio agents ride the user's token
  (agent CA is a no-op; the user's CA + Purview DLP-for-AI govern them), while
  only autonomous **S2S** agents are gated by agent CA.
- **4 · Exploitation** — the injection chain: untrusted input → Work IQ reads
  sensitive data → an egress tool carries it out. Three attack paths are traced
  (compromised user, prompt injection, compromised blueprint).
- **Agents** — the per-agent inventory and derived Work-IQ reach.
- **Demo lab** — a client-side, *simulated* walkthrough of two scenarios
  (**Compromised user**, **Prompt injection**) that animates the exposure; it
  needs no tenant, but it is illustrative only, not a scan of your data.

Reach is derived from each agent's tools / MCP servers / connectors (Defender
`AgentsInfo`, optional) and from its Graph data-read permissions (own +
blueprint-inherited). Optional signals degrade gracefully with a notice.

---

## Requirements

- A **single-tenant Single-page application (SPA)** app registration, with this
  page's URL as the **SPA redirect URI**.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- An account with admin consent for the scopes below and a role that can read
  agent identities (e.g. **Global Reader** or **Agent ID Administrator**).

### Microsoft Graph permissions (delegated, read-only, admin consent)

**Required — the scan cannot start without these:**

| Scope | Why |
|-------|-----|
| `AgentIdentity.Read.All` | modern agent identities |
| `Application.Read.All` | service principals |
| `Directory.Read.All` | directory objects, licences |
| `User.Read` | sign-in |

**Optional — each degrades gracefully:**

| Scope | Why |
|-------|-----|
| `ThreatHunting.Read.All` | each agent's real Work-IQ tools & MCP servers from Defender `AgentsInfo` (without it, reach falls back to Graph data-read permissions only, which understate OBO reach) |
| `InformationProtectionPolicy.Read` | Purview sensitivity labels reachable on a user's behalf |
| `Policy.Read.All` | Conditional Access for agents (note: agent CA only gates autonomous S2S agents) |

---

## How to run

1. Open the page over http(s) (e.g. via `blue16.nl`, GitHub Pages, or any static
   host). `file://` will not work.
2. Register the page URL as a **SPA** redirect URI on a single-tenant app
   registration and grant admin consent for the four required scopes (add the
   optional ones for tool/MCP wiring, labels and CA).
3. Enter the **Application (client) ID** and **Directory (tenant) ID or domain**
   (`organizations` if unsure), pick the Graph version (`v1.0` is GA for
   `agentIdentity`; `beta` exposes extra properties).
4. **Sign in & scan**, then move through Posture → Exposure → Risk →
   Exploitation, or open the **Agents** inventory.

To explore the concept without a scan, open the **Demo lab** and run one of the
simulated scenarios — no tenant or sign-in is needed for that view.

---

## Privacy & safety

- **Read-only.** Every requested scope is a `*.Read*` delegated permission;
  nothing the tool requests writes to the tenant.
- **No backend.** All Graph and advanced-hunting calls run from your browser with
  your delegated token (cached in `sessionStorage`); results are rendered locally
  and never sent anywhere by the tool.
- Client ID / tenant ID / Graph version are remembered in `localStorage` for
  convenience only. The Demo lab is fully client-side and simulated.

---

## Limitations

- Preview: the reach model, risk logic and Work IQ facts follow Microsoft's Agent
  365 model and may drift from your tenant's reality — verify anything that looks
  off.
- Work IQ runs **OBO**, so the tool shows the *surface* (which domains an agent
  can touch), not per-user entitlements; it does not read per-user access, CA or
  DLP-for-AI outcomes.
- Without `ThreatHunting.Read.All`, tool/MCP wiring is not read and reach falls
  back to Graph data-read permissions only, understating OBO reach; label and CA
  signals likewise need their optional scopes.
- The Demo lab is a scripted simulation, not a measurement of your tenant.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
