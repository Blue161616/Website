# Entra External Access Posture (Preview)

See who can reach your tenant from outside it, by which mechanism, and with what
trust delegated — read straight from your Microsoft Entra cross-tenant access
policy. It runs entirely in your browser against Microsoft Graph — **read-only**,
no backend, no data leaves the page.

- **File:** `entra-external-access-posture.html`
- **Identity type / Category:** External access (cross-tenant access, B2B, guests)
- **Status:** Preview

---

## What it does

Reads the cross-tenant access policy as Graph returns it — the default
configuration, the per-partner overrides, and cross-tenant synchronisation — and
raises graded **findings** (high / medium / critical). Nothing is written. The
findings are grouped so you can see where each one lands:

- **Default configuration (baseline)** — B2B collaboration inbound/outbound,
  B2B direct connect, and whether device/MFA trust is accepted from every tenant
  by default. Direct connect is called out because it grants access without
  creating a reviewable guest object.
- **Per-partner overrides** — each partner entry, what it allows, and where a
  partner has cross-tenant synchronisation configured (a partner provisioning
  user objects directly into your directory).
- **Guests** — guest accounts correlated to their partner tenants, so a partner
  you trust with open inbound collaboration is tied to the guests it produced.

Unreadable signals report themselves as unevaluated rather than as zero, so an
absent read never looks like a clean result. Findings can be copied out with the
**Copy findings** button.

---

## Requirements

- A **Single-page application (SPA)** app registration (not a *Web* platform — a
  Web registration fails the token exchange with a cross-origin redemption
  error).
- The page's own URL registered as a **SPA redirect URI**.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- Admin consent (a Global Administrator must consent tenant-wide), and a
  signed-in account with a role that may read the policy: **Global Reader**,
  **Security Reader** or **Security Administrator** read everything; Global
  Reader is the least that produces a complete report. Global Secure Access
  Administrator and Teams Administrator can read partner configuration but not
  cross-tenant synchronisation, and the sync column says so.

### Microsoft Graph permissions (delegated, read-only, admin consent)

**Required — the scan cannot start without this:**

| Scope | Why |
|-------|-----|
| `Policy.Read.All` | the cross-tenant access policy itself |

**Optional — each degrades gracefully:**

| Scope | Why |
|-------|-----|
| `CrossTenantInformation.ReadBasic.All` | names partner tenants instead of listing raw GUIDs (every finding still fires without it) |
| `User.Read.All` | correlate guests to their partner tenants (without it, guest correlation reports itself unevaluated, not zero) |

---

## How to run

1. Open the page over http(s) (e.g. via `blue16.nl`, GitHub Pages, or any static
   host). `file://` will not work.
2. Register the page URL as a **SPA** redirect URI on an app registration. Use
   **Grant admin consent** to send an administrator to the tenant-wide consent
   screen for these permissions.
3. Enter the **App registration client ID**. Leave the tenant ID blank for a
   multi-tenant registration; fill it in for a single-tenant app (Entra refuses
   the shared `/common` endpoint for single-tenant apps created after 2018 with
   `AADSTS50194`).
4. Sign in with Microsoft and review the findings, grouped by baseline, partners
   and guests. Use **Copy findings** to export.

---

## Privacy & safety

- **Read-only.** The tool only reads the cross-tenant access policy; nothing is
  written. Every scope requested is a read-only, delegated permission.
- **No backend.** Graph calls run from your browser with your delegated token,
  and the client ID is stored in this browser only; results are rendered locally
  and never sent anywhere by the tool.
- Least privilege — only `Policy.Read.All` is required; the two name-resolution
  and guest-correlation scopes are optional and additive.

---

## Limitations

- Without `CrossTenantInformation.ReadBasic.All`, partners are listed by tenant
  ID rather than name (though a partner with cross-tenant sync still supplies its
  display name).
- Without `User.Read.All`, guest correlation is reported as unevaluated.
- An account that cannot read cross-tenant synchronisation (e.g. Global Secure
  Access / Teams Administrator) sees the sync column marked unreadable, with a
  finding, rather than a false all-clear.
- Preview: findings and checks may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
