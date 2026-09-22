# Power Platform Security Posture (Preview)

Score each Power Platform environment on a security baseline and surface the
findings that decide it — risky connectors, agent authentication, DLP coverage
and privileged access. It runs entirely in your browser against the **Dataverse
Web API** and, best-effort, the **Power Platform admin API** — **read-only**, no
backend, no data leaves the page.

- **File:** `power-platform-security-posture.html`
- **Category:** Power Platform
- **Status:** Preview

---

## What it does

Enumerates the environments you can reach and computes a per-environment baseline,
worst-first, with a tenant-wide gauge and findings grouped by category:

- **Risky connectors** — connectors whose presence is a data-movement,
  exfiltration or privilege signal (HTTP, SQL, Azure Blob/Cosmos, FTP/SFTP,
  Service Bus/Queues, Office 365, SharePoint, OneDrive, Dropbox/Box/Google Drive,
  Azure AD, cloud/desktop flows, and more), plus detection of custom connectors.
- **Agent authentication** — agents with no or weak authentication.
- **DLP coverage** — whether a tenant DLP policy covers each environment, once you
  import the policy export (see below); reads as *unknown* without it.
- **Environment type** — flags the **Default** environment (via
  `environmentSku = "Default"`), which carries the most risk.
- **Privileged access, connectors and flows** — expandable per-environment detail
  with per-finding remediation.

Results render as a posture grade, summary tiles, a risk-exposure bar chart and a
sortable environment table. Findings export to CSV.

---

## Requirements

- A **Single-page application (SPA)** app registration (not a *Web* platform — a
  Web registration fails the token exchange with a cross-origin redemption error).
- The page's own URL registered as a **SPA redirect URI**.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- **Power Platform Administrator** or **Global Admin** for the tenant-wide
  environment list, plus a **Dataverse security role** in each environment you
  want scanned (an environment you cannot read is skipped silently).

The page ships pre-filled with Blue16's published, read-only app
(`96e9b5f4-e974-4355-ae9f-4487099ef210`); the MSAL authority is `organizations`.

### API permissions (delegated)

| Scope / API | Why |
|-------|-----|
| `User.Read` (Microsoft Graph) | sign-in only |
| `user_impersonation` (Dynamics CRM) | **required** — environment scan |
| `EnvironmentManagement.Environments.Read` (Power Platform API, `8578e004-a5c6-46e7-913e-12f58912df43`) | *optional* — full environment list, type and Default flag; without it the tool only sees environments where you hold a Dataverse role and cannot tell which is Default |

> **Tenant DLP cannot be read from the browser and no role fixes that.** The legacy
> admin API (`api.bap.microsoft.com`) is not grantable to a custom app registration
> and browsers block it via CORS; the Power Platform API exposes no DLP scope. Being
> Global Admin grants the *authorisation* but never the *token*.

---

## How to run

1. Serve the page over http(s). `file://` will not work.
2. Register the page URL as a **SPA** redirect URI, add the permissions above and
   grant admin consent.
3. Enter the **Client ID**, then either paste **environment URLs** or click
   **Discover my environments**.
4. *(Optional but recommended)* Export tenant DLP as an admin and import
   `dlp.json` so DLP coverage becomes a per-environment answer rather than a guess:
   ```powershell
   Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser
   Add-PowerAppsAccount
   Get-DlpPolicy | ConvertTo-Json -Depth 10 | Set-Content dlp.json
   ```
   The import stays in your browser and is a point-in-time copy — re-export after
   any policy change.
5. Click **Sign in & scan** and review the baseline and findings.

---

## Privacy & safety

- **Read-only.** The tool only reads environment, agent, connector and DLP data;
  it never writes.
- **No backend.** All calls run from your browser with your delegated token; the
  imported DLP export is held in `localStorage` only. Nothing is sent anywhere by
  the tool.
- Tenant DLP / governance is attempted and **degrades gracefully** when the
  browser blocks it — the baseline is then computed excluding DLP gaps and may
  read better than reality.

---

## Limitations

- Coverage is limited to environments where your account has a Dataverse security
  role; others are skipped silently, which can look like a clean result.
- Without the imported DLP export, DLP coverage reads as unknown and the baseline
  omits DLP gaps.
- Without the optional Power Platform API permission, the Default-environment flag
  and full tenant environment list are unavailable.
- No demo mode: the tool requires a real sign-in and at least one environment.
- Preview: scoring weights and checks may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
