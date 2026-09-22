# Entra Workload Security Posture (Preview)

Risk-score every consented enterprise application and service principal in your
Microsoft Entra tenant, then map a per-app attack path with remediation. It runs
entirely in your browser against Microsoft Graph — **read-only**, no backend, no
data leaves the page.

- **File:** `entra-risky-apps-webapp.html`
- **Identity type:** Workload (service principals / enterprise apps)
- **Status:** Preview

---

## What it does

Enumerates every app registration and service principal in the tenant and scores
each one **0–100** on the signals that decide how dangerous a workload identity
is if it were abused:

- **Permissions** — every delegated and application (app-only) Graph permission
  each app holds, classified by risk category (identity, privilege, security,
  data, mail, …) and severity. High-blast-radius grants such as full directory
  read, application-management or role-management rights are called out.
- **Directory roles held by service principals** — the authorisation behind a
  capability permission (e.g. `Exchange.ManageAsApp` does nothing without a role
  behind it).
- **Credential hygiene** — client secrets and certificates, their age and
  expiry.
- **Tenancy & publisher trust** — single- vs multi-tenant, Microsoft vs
  third-party, publisher-verified or not.
- **Risky workload identities** — what Entra ID Protection concluded about each
  service principal (risk state, level, detail), when the Workload ID licence is
  present.
- **Conditional Access for workload identities** — which enabled or report-only
  policies include each service principal, and which single-tenant apps no policy
  covers.
- **Usage** — whether and when each app actually authenticated app-only, and with
  which credential (needs sign-in logs / Entra ID P1/P2).

Each app gets a grade, a per-app attack-path view, and concrete remediation. A
detail drawer can edit an app's redirect URIs in place (the only write action —
see permissions).

---

## Requirements

- A **Single-page application (SPA)** app registration in the tenant you want to
  assess (not a *Web* platform — a Web registration fails the token exchange with
  a cross-origin redemption error).
- The page's own URL registered as a **SPA redirect URI**.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- An account that can grant (or has been granted) admin consent for the scopes
  below. For the risky-workload and CA-policy signals, the signed-in account
  needs **Global Reader** or **Security Reader**.

### Microsoft Graph permissions (delegated, read-only, admin consent)

**Required — the scan cannot start without these:**

| Scope | Why |
|-------|-----|
| `Application.Read.All` | app registrations and service principals |
| `DelegatedPermissionGrant.Read.All` | delegated consent grants |

**Optional — each degrades gracefully; an absent one is reported as *not
assessed*, never as a clean result:**

| Scope | Why |
|-------|-----|
| `RoleManagement.Read.Directory` | directory roles held by service principals |
| `AuditLog.Read.All` | app-only sign-in usage detection (needs Entra ID P1/P2) |
| `Organization.Read.All` | Workload ID Premium (`AAD_WRKLDID_P2`) licence check |
| `IdentityRiskyServicePrincipal.Read.All` | risky workload identities (Entra ID Protection) |
| `Policy.Read.All` | Conditional Access for workload identities |
| `Application.ReadWrite.All` | **only** to edit an app's redirect URIs from the detail drawer |

> The one write scope (`Application.ReadWrite.All`) is requested **at the moment
> you use it**, not at sign-in — a session that edits nothing never asks for it.

---

## How to run

1. Open the page over http(s) (e.g. via `blue16.nl`, GitHub Pages, or any static
   host). `file://` will not work.
2. Register the page URL as a **SPA** redirect URI on an app registration, and
   grant admin consent for at least the two required scopes.
3. Enter the **Application (client) ID** and **Directory (tenant) ID or domain**
   (`organizations` if unsure), pick the Graph API version (`v1.0` is GA for the
   app & consent APIs), and connect.
4. Review the scored inventory; open any app for its attack path and remediation.

### Try it without a tenant — Demo mode

Append `?demo` to the URL (or use the demo link in the page) to load a **synthetic
tenant**: no sign-in, nothing fetched from Graph. Every number is generated and
scored by exactly the same rules a real scan uses — a safe way to see the output.

---

## Privacy & safety

- **Read-only by default.** Nothing is written except the optional redirect-URI
  edit, which asks for its write scope only when used.
- **No backend.** All Graph calls run from your browser with your delegated
  token; results are rendered locally and never sent anywhere by the tool.
- Delegated, admin-consented, least-privilege scopes — the two required are the
  floor; everything else is optional and additive.

---

## Limitations

- Multi-tenant and Microsoft-published apps are outside what workload-identity
  Conditional Access policies can reach, so they show as *not covered* by design.
- Risky-workload and app-only usage signals depend on the corresponding licences
  (Workload ID Premium, Entra ID P1/P2); without them those rows read *not
  assessed*.
- Preview: scoring weights and checks may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
