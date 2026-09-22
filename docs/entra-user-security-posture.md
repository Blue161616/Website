# Entra User Security Posture (Preview)

Score every member account in your Microsoft Entra tenant on the signals that
decide how exposed a user identity is — MFA, privileged access, account hygiene
and Identity Protection risk. It runs entirely in your browser against Microsoft
Graph — **read-only**, no backend, no data leaves the page.

- **File:** `entra-user-security-posture.html`
- **Identity type:** User (member accounts)
- **Status:** Preview

---

## What it does

Enumerates member accounts and scores each one **0–100** (higher = worse) across
four dimensions, then shows a per-user breakdown, roles, account facts and
remediation:

- **MFA posture** — the account's registered authentication methods and last
  sign-in staleness. It also separates *registered* from *enforced*: the
  Conditional Access column is the authoritative MFA check, because a registered
  method that no policy enforces is not protection.
- **Privileged access** — directory roles held, including the service principals
  behind role holders. PIM eligibility is folded in; an eligible role that
  requires **approval** to activate is scored lower than one that self-activates.
- **Account hygiene** — account-level facts that raise or lower exposure.
- **Identity Protection risk** — each user's risk state from Entra ID Protection
  (needs Entra ID P2).

Absent optional signals are reported as *not assessed* rather than as a clean
result — a missing licence or scope never reads as a pass.

---

## Requirements

- A **Single-page application (SPA)** app registration in the tenant you want to
  assess (not a *Web* platform — a Web registration fails the token exchange with
  a cross-origin redemption error).
- The page's own URL registered as a **SPA redirect URI**.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- Admin consent for the scopes below, and a signed-in account with a directory
  role that can read them. **Global Reader** is enough for everything on this
  page and grants no write anywhere; without it the scan returns few or no users,
  which looks like a small tenant rather than a blocked read.

### Microsoft Graph permissions (delegated, read-only, admin consent)

**Required — the scan cannot start without these:**

| Scope | Why |
|-------|-----|
| `Directory.Read.All` | users, groups, licences |
| `RoleManagement.Read.All` | directory role assignments — who is privileged |
| `Application.Read.All` | service principals behind role holders |
| `User.Read` | sign-in |

**Optional — each degrades gracefully; an absent one is reported as *not
assessed*:**

| Scope | Why |
|-------|-----|
| `AuditLog.Read.All` | per-user MFA-method posture and last-sign-in staleness |
| `Policy.Read.All` | whether each admin is covered by an *enforcing* MFA Conditional Access policy |
| `IdentityRiskyUser.Read.All` | Entra ID Protection risk (needs Entra ID P2) |
| `Organization.Read.All` | Entra ID P2 licence check (via the `AAD_PREMIUM_P2` service plan) — also names privileged accounts holding no P2 seat |
| `RoleManagementPolicy.Read.Directory` | which eligible roles require approval to activate — lowers the score for approval-gated eligibility |

> PIM eligibility (`roleEligibilityScheduleInstances`) is read with the role
> permissions already granted; it returns nothing without a P2 licence.

---

## How to run

1. Open the page over http(s) (e.g. via `blue16.nl`, GitHub Pages, or any static
   host). `file://` will not work.
2. Register the page URL as a **SPA** redirect URI on an app registration, and
   grant admin consent for at least the four required scopes.
3. Enter the **Application (client) ID** and **Directory (tenant) ID or domain**
   (`organizations` if unsure), pick the Graph API version (`v1.0` is GA), and
   sign in.
4. Review the scored accounts; click any row for its score breakdown, roles,
   account facts and remediation.

### Try it without a tenant — Demo mode

Append `?demo=1` to the URL (or use the demo link in the page) to load a
**synthetic tenant**: no sign-in, nothing fetched from Graph. Every account is
generated and scored by exactly the same rules a real scan uses — a safe way to
see the output.

---

## Privacy & safety

- **Read-only.** Nothing on this page writes; every scope requested is a
  read-only, admin-consented, delegated permission.
- **No backend.** All Graph calls run from your browser with your delegated
  token; results are rendered locally and never sent anywhere by the tool.
- Least privilege — the four required scopes are the floor; everything else is
  optional and additive, and Global Reader is enough to read them all.

---

## Limitations

- MFA, Conditional Access, risk and PIM-approval signals each depend on the
  corresponding scope; without it those rows read *not assessed*, not clean.
- Identity Protection risk and PIM eligibility need an **Entra ID P2** licence;
  without it those signals stay empty.
- Preview: scoring weights and checks may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
