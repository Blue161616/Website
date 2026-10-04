# Entra Confirm Compromised (Preview)

Act on Microsoft Entra ID Protection risk for **users, workload identities and
agents** from one page: list every identity with its live risk state, confirm one
or more as compromised (or safe), and see straight away whether a Conditional
Access policy will actually enforce it. It runs entirely in your browser against
Microsoft Graph — no backend, no data leaves the page.

- **File:** `entra-confirm-compromised.html`
- **Identity type / Category:** Users, workload identities and agents (identity risk response)
- **Status:** Preview

---

## What it does

- **Lists all identities with their ID Protection status.** On sign-in it loads
  users, workload identities (service principals) and agent identities, merges
  each with its risky-object record and shows risk level, risk state, risk detail
  and last update. Tiles summarise loaded / at risk / high / medium / low /
  confirmed compromised and filter the table on click. Microsoft first-party apps
  and managed identities are hidden by default, as workload identity risk does
  not cover them.
- **Confirm compromised, in bulk.** Select one or more identities and type
  `CONFIRM`. The action sets risk to **High** with state `confirmedCompromised`.
- **Confirm safe / dismiss.** Clears the state for false positives: *Confirm
  safe* for users and agents, *Dismiss risk* for workload identities (Graph has
  no `confirmSafe` for service principals).
- **Status per identity.** Risk detections (with IP and location for users) and
  risk history, read live from Graph.
- **Conditional Access coverage.** One animated flow from *Confirm compromised*
  through *ID Protection* to the CA policy and outcome for each identity type. It
  reads your CA policies and finds the one acting on High risk per type, then
  shows whether it is On, report-only or off, what it enforces, and whether the
  required licence is present. Exclusions and policies that do not target *All
  resources* are flagged.

| Identity type | Action endpoint | CA condition | Licence checked |
|---|---|---|---|
| Users | `v1.0 /identityProtection/riskyUsers/confirmCompromised`, `/confirmSafe` | `userRiskLevels` | Entra ID P2 |
| Workload identities | `v1.0 /identityProtection/riskyServicePrincipals/confirmCompromised`, `/dismiss` | `servicePrincipalRiskLevels` | Workload ID Premium |
| Agents | `beta /identityProtection/riskyAgents/confirmCompromised`, `/confirmSafe` | `agentIdRiskLevels` (beta) | Entra ID P2 (preview), Agent 365 (announced) |

---

## Requirements

- A **Single-page application (SPA)** app registration with the page's own URL
  as a SPA redirect URI.
- The page **served over http(s)** — MSAL cannot run from `file://`.
- Admin consent, and a signed-in account with:
  - **Security Administrator** to confirm compromised, confirm safe or dismiss.
  - **Security Reader**, **Security Operator** or **Global Reader** to view status
    and read CA policies.
  - **Global Reader** or **Directory Readers** for the licence check.
- Licensing per identity type as in the table above.

### Microsoft Graph permissions (delegated, admin consent)

| Scope | Why |
|-------|-----|
| `IdentityRiskyUser.ReadWrite.All` | read and act on risky users |
| `IdentityRiskyServicePrincipal.ReadWrite.All` | read and act on risky workload identities |
| `IdentityRiskyAgent.ReadWrite.All` | read and act on risky agents |
| `IdentityRiskEvent.Read.All` | risk detections in the status view |
| `User.ReadBasic.All` | list users |
| `Application.Read.All` | list service principals |
| `AgentIdentity.Read.All` | list agent identities |
| `Policy.Read.All` | Conditional Access coverage check |
| `LicenseAssignment.Read.All` | licence check |

Each tab only requests the scopes it needs; the coverage check and licence chips
report themselves as unreadable rather than as a false all-clear when a scope or
role is missing.

---

## How to run

1. Open the page over http(s) (e.g. via `blue16.nl`, GitHub Pages, or
   `python -m http.server`).
2. Register the page URL as a **SPA** redirect URI on an app registration and
   grant admin consent for the scopes above.
3. Enter the **Application (client) ID** and the tenant (use the tenant ID or
   domain for a single-tenant app).
4. Sign in. All three identity types and the CA coverage check load
   automatically; the app registration panel hides (reopen it from the header).
5. Select identities, then **Confirm compromised…** or **Confirm safe…**. Use the
   **Status** button on a row for detections and history.

---

## Privacy & safety

- **Writes only on explicit confirmation.** Every state change asks you to type
  `CONFIRM`; each request (endpoint, status code, object IDs) is written to the
  action log, which can be copied for case notes.
- **No backend.** Graph calls run from your browser with your delegated token;
  the client ID is stored in this browser only.
- The last access token is decoded locally so you can verify `scp` and `wids`
  (active roles) without leaving the page.

---

## Limitations

- Agent risk and `agentIdRiskLevels` are beta / preview; Graph shapes may change.
- Confirming compromise changes risk state only. Enforcement happens at the next
  token request, so issued workload and agent tokens stay valid until expiry —
  rotate credentials or disable the identity for immediate containment.
- The directory list stops at 20,000 objects per type; use **Search directory**
  beyond that.
- The coverage check evaluates policies that include High risk; it does not
  simulate every condition (locations, devices, filters).
- Preview: checks and layout may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
