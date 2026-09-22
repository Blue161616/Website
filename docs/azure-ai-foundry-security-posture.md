# Azure AI Foundry Security Posture (Preview)

Risk-score the AI resources across every Azure subscription you can read —
Cognitive Services / Azure OpenAI accounts and AI Foundry hubs & projects — on
exposure, authentication, identity, data protection and governance, then check the
guardrails, the AI gateway and whether Defender for Cloud is watching them at
runtime. It runs entirely in your browser against **Azure Resource Manager (ARM)**
via **Azure Resource Graph** — **read-only**, no backend.

- **File:** `azure-ai-foundry-security-posture.html`
- **Category:** Azure AI
- **Status:** Preview

---

## What it does

Sweeps `microsoft.cognitiveservices/accounts`,
`microsoft.machinelearningservices/workspaces` and
`microsoft.apimanagement/service` with one Resource Graph query, then scores each
AI resource **0–100** and raises findings:

- **Exposure** — public network access open, and (candidate) AI Gateway coverage
  via a v2-tier API Management instance in the same subscription.
- **Authentication** — local auth (API keys) enabled.
- **Identity** — no managed identity assigned.
- **Data protection & governance** — no diagnostic logging, and other config
  facts per resource.
- **Guardrails (RAI policies)** — which risk categories each model deployment's
  Responsible AI policy actually covers, calling out the agentic gaps that matter
  once an agent has tools and web grounding: **indirect prompt injection**,
  **sensitive data (PII)** and **task drift**.
- **Agent-level guardrails** — for Foundry agents, the effective guardrail
  (the agent's own, else the model deployment's, else none), honestly labelled by
  source.
- **Defender for Cloud** — whether the AI Services plan is watching each
  subscription at runtime.
- **AI red teaming** — an explainer of what Foundry's red-teaming scan covers and
  which agent tool types it can and cannot exercise.

Results render across Overview, Gateway, Red teaming and Agents views with a
tenant grade, summary tiles and a filterable table. Findings export to CSV/JSON.

---

## Requirements

- A **Single-page application (SPA)** app registration you control (not a *Web*
  platform — a Web registration rejects the token exchange with a cross-origin
  redemption error).
- The page's own URL registered as a **SPA redirect URI**.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- **Azure RBAC role assignments** — delegated tokens act as the signed-in user, so
  the API permission grants nothing on its own. Each user needs **Reader** on
  every subscription whose AI resources should be assessed; a subscription you
  cannot read is skipped silently.

### API permissions (delegated, no admin consent needed)

| Scope / API | Why |
|-------|-----|
| `user_impersonation` (Azure Service Management, audience `management.azure.com`) | **required** — resources, deployments, guardrail (RAI) policies and Defender plans; covers the whole management plane |
| `user_impersonation` (Azure AI Foundry, `https://ai.azure.com`) | *optional* — reads **Foundry agents** on the data plane so an agent's own guardrail can be told from its model's; requested silently/on demand, offered as a button when unread |

Without the optional Foundry scope the page still reports guardrail coverage per
model deployment and states plainly that the agent layer was not read — it never
presents a model's guardrail as though it were the agent's.

---

## How to run

1. Serve the page over http(s). `file://` will not work.
2. Register the page URL as a **SPA** redirect URI, and add the Azure Service
   Management `user_impersonation` delegated permission.
3. Ensure your account holds **Reader** on the subscriptions to assess.
4. Enter the **Client ID** and **tenant** (`organizations` if unsure), then
   **Sign in & scan**.
5. Review the scored resources across the four views; if a hub or account you
   expect is absent, check the role assignment before the finding list.

---

## Privacy & safety

- **Read-only.** Every call is a GET/POST query to ARM; the tool never changes
  configuration.
- **No backend.** All calls run from your browser with your delegated token;
  nothing leaves your browser except the calls to `management.azure.com` (and, if
  consented, the Foundry data plane at `ai.azure.com`).
- The MSAL token cache uses `sessionStorage`, so it clears when the tab closes.

---

## Limitations

- A subscription you cannot read is skipped silently, which looks like a clean
  result rather than a missing one.
- **AI Gateway** association cannot be proven from ARM at the current API version,
  so an eligible v2-tier APIM instance is reported as a *candidate*, not a link.
- Agent-level guardrails require the optional Foundry data-plane token; without it
  (or if the browser blocks the host) the agent layer is reported as unread.
- No demo mode: the tool requires a real Azure sign-in.
- Preview: scoring and several guardrail/agent property reads rely on preview APIs
  whose schema may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
