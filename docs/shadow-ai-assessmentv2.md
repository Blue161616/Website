# Shadow AI Security Assessment V2 (Preview)

Discover GenAI and Shadow-AI usage across your Microsoft Entra tenant and score
its risk. It runs entirely in your browser against Microsoft Graph with a
delegated MSAL token — **read-only**, no backend, no data leaves the page — and
surfaces AI apps, models, agents, Copilot usage and the data they can reach.

- **File:** `shadow-ai-assessmentv2.html`
- **Category:** AI exposure
- **Status:** Private Preview (restricted)

---

## What it does

- Inventories AI-related **enterprise apps and service principals**, the OAuth
  scopes they hold, and flags **high-risk grants** (Mail, Files, Calendar,
  Sites, Directory access) and **tenant-wide consent grants** every user
  silently carries.
- Detects **third-party / external LLM usage**, apps that may **train on your
  prompts**, and apps **routing data to China** (data-residency / DPA concerns).
- Maps **AI agents** (Copilot agent blueprints and identities), **Copilot
  usage**, and **MCP servers**.
- Correlates **risky users, service principals and agents** from Entra ID
  Protection and **Defender XDR alerts** with AI-app access.
- Assesses **data exposure**: Purview sensitivity labels reachable by AI apps,
  and SharePoint/OneDrive external-sharing posture.
- Checks **governance**: Conditional Access coverage of AI apps, Security
  Defaults, and whether users can register apps.
- Presents this as a dashboard plus pages: Shadow AI Apps, AI Models, AI Agents,
  Copilot Usage, MCP Servers, Data Risk, Purview Sensitivity Labels,
  SharePoint/OneDrive Sharing, AI & Agent Users, and Licenses.

---

## Requirements

The tool **signs in to Microsoft Graph** — it does not ingest a file. It ships
with Blue16's published, read-only **multi-tenant** app registration and fills
in its own redirect URI, so most tenants only need admin consent plus the right
roles; you can also register your own SPA app instead. Every scope is delegated
and **read-only**, but a **Global Administrator must grant admin consent**
tenant-wide before any of them work.

### Microsoft Graph permissions (delegated, read-only, admin consent)

| Scope / Input | Why |
|-------|-----|
| `Application.Read.All` | service principals / enterprise apps |
| `AuditLog.Read.All` | sign-ins to AI apps |
| `User.Read.All` | user context for AI/agent usage |
| `Policy.Read.All` | Conditional Access & auth policy |
| `Organization.Read.All` | tenant / licence context |
| `RoleManagement.Read.All` | directory roles |
| `CloudApp-Discovery.Read.All` | discovered cloud (Shadow AI) apps |
| `Reports.Read.All` | usage reports |
| `IdentityRiskyUser.Read.All` | risky users *(needs Entra ID P2)* |
| `IdentityRiskyServicePrincipal.Read.All` | risky service principals *(Entra ID P2)* |
| `IdentityRiskyAgent.Read.All` | risky AI agents *(Entra ID P2)* |
| `SecurityAlert.Read.All` | Defender XDR alerts *(needs Defender licensing)* |
| `SecurityEvents.Read.All` | Defender XDR security events *(Defender licensing)* |
| `AgentIdentityBlueprint.Read.All` | Copilot agent blueprints *(preview API)* |
| `AgentIdentity.Read.All` | agent identities *(preview API)* |
| `AgentIdentityBlueprintPrincipal.Read.All` | agent blueprint principals *(preview API)* |
| `InformationProtectionPolicy.Read` | Purview label policy |
| `SensitivityLabel.Read` | sensitivity labels |
| `SharePointTenantSettings.Read.All` | SharePoint sharing settings |

Optional / incremental scopes, requested separately (not in the core sign-in
token): `ThreatHunting.Read.All` (Defender Advanced Hunting), `CopilotPolicySettings.Read`
(Copilot policy), `ProtectionScopes.Compute.User` (Purview DLP scope).

The signed-in account also needs **Security Reader or higher**; without it,
sign-in logs return zero rows rather than an error.

---

## How to run

1. Serve the page over **http(s)** — MSAL cannot run from `file://`.
2. Use the shipped multi-tenant registration, or register your own **Single-page
   application** (SPA) platform with this page's URL as the **SPA redirect URI**
   and account type set to **multi-tenant**. A *Web* registration fails the
   token exchange with a cross-origin redemption error.
3. Have a **Global Administrator** click **Grant / re-run admin consent** so the
   delegated scopes take effect (re-run it after adding any permission).
4. **Sign in with Microsoft** using an account that holds Security Reader or
   higher, then review the Dashboard and the per-area pages.

---

## Privacy & safety

- **Read-only.** Every requested scope is a delegated `*.Read*` scope; the tool
  never writes to the tenant.
- **No backend.** All Graph calls run from your browser with your delegated
  token; results are rendered locally and never sent anywhere by the tool.
- A "Test with mock data" control on the consent timeline loads synthetic rows
  for UI verification only — it is not a full offline demo mode.

---

## Limitations

- **Restricted private preview.** Access is limited; the tool relies on preview
  Graph APIs (the AI Agents scopes) that do not exist in every tenant yet.
- Licence-gated data fails **silently**: without **Entra ID P2** the Identity &
  Risk group returns nothing, and without **Microsoft Defender** licensing the
  Security group returns no alerts — each reads as a clean result, so confirm
  roles and licences before treating a quiet report as good news.
- Consent alone is not enough — the signed-in account still needs the matching
  directory role, or data comes back empty.
- Scoring weights, pages and preview APIs may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
