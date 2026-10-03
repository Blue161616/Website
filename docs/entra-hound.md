# EntraHound (Preview)

Attack path and identity exposure management for Microsoft Entra ID. EntraHound
reads a tenant through Microsoft Graph and turns it into a **directed security
graph**: every identity, group, role, application, service principal, managed
identity, device, AI agent, federated issuer and policy is a node; every
membership, ownership, role assignment, credential, permission grant and trust is
an edge. It then answers the question that matters:

> Which combinations of identities, permissions, ownership, credentials and trust
> relationships create a path to our critical assets?

It runs entirely in your browser — **read-only**, no backend, no data leaves the
page.

- **File:** `entra-hound.html`
- **Scope:** all Entra identity types and the relationships between them
- **Status:** Preview

---

## Pipeline

```
Microsoft Graph → Collector → Normalisation → Relationship engine → In-memory graph
              → Attack path engine → Risk engine → Findings → Dashboard / Explorer / Query / Export
```

The raw collection is stored as received and never mutated; the graph, paths,
risk scores and findings are derived from it. Everything is exportable.

## Connecting

Three ways in:

1. **Interactive sign-in** — a single-page-application registration in the tenant
   (redirect URI `https://blue16.nl/entra-hound.html`). Delegated permissions;
   what you see is the intersection of the app's consent and your own role.
   Global Reader or Security Reader is enough. Global Administrator is never
   required.
2. **External token** — paste an access token for `https://graph.microsoft.com`
   minted outside the browser with a certificate, client secret or managed
   identity. The token stays in the tab's memory.
3. **Demo tenant** — a synthetic Contoso with deliberately planted exposure, to
   explore the tool without a tenant.

### Permissions

| Permission | Unlocks |
|---|---|
| `Directory.Read.All` (**required**) | organisation, domains, licences, users, groups + owners + members, app registrations + owners + federated credentials, service principals + owners, application permission grants, delegated consent, directory roles + members, role definitions, role assignments (incl. AU-scoped), administrative units, devices |
| `Policy.Read.All` | Conditional Access policies (coverage and exclusions), security defaults, authorization policy, cross-tenant access settings, authentication strengths |
| `RoleManagement.Read.Directory` | PIM eligible and time-bound active assignments |
| `AuditLog.Read.All` | last sign-in per user (dormancy) |
| `UserAuthenticationMethod.Read.All` | MFA registration per user |
| `AgentIdentityBlueprint.Read.All`, `AgentIdentity.Read.All`, `AgentIdentityBlueprintPrincipal.Read.All` | agent identities, blueprints, owners and sponsors |

Optional permissions are tried silently. A missing one is reported per source
under **Collection** and the affected edges or findings simply do not appear.

Collection is rate-limit aware (`429` → `Retry-After`), uses `$batch` for
per-object reads, is tenant-scoped, and logs every request (exportable).

## The graph

**Node types:** user, guest, group, directory role (tenant-wide and AU-scoped),
app registration, service principal, managed identity, device, agent identity,
agent blueprint, tenant, resource API, permission, external issuer (federated
credential or on-premises AD), partner tenant, administrative unit, CA policy.

**Edge kinds:** `MemberOf`, `OwnerOf`, `AssignedRole`, `EligibleRole`,
`ScopedRole`, `RunsAs`, `HasApplicationPermission`, `HasDelegatedPermission`,
`FederatedWith`, `SyncedFromAD`, `CanBecome`, and the derived capability edges
`CanAddCredential`, `CanModifyGroupMembership`, `CanResetPassword`,
`CanModifyAuthenticationMethods`, `CanAssignRole`, `CanGrantConsent`,
`CanModifyConditionalAccess`, `CanModifyFederation`, `CanControl`. Informational
(non-traversable) edges: `CreatedFrom`, `SponsorOf`, `ManagerOf`,
`RegisteredOwnerOf`, `TrustedBy`, `ExcludedFrom`, `MemberOfAU`.

Every edge carries a mode — `DIRECT`, `INHERITED` (derived from a role or
permission), `ELIGIBLE` (needs PIM activation) or `CONDITIONAL` (depends on a
user signing in, or a wildcard trust) — and a weight the path engine uses.

Capability edges are derived from what a role or Graph permission lets its
holder do, and only towards targets that themselves lead somewhere, so an
Application Administrator gets `CanAddCredential` edges to privileged apps, not
to every app in the tenant.

## Critical assets

Marked automatically: Tier-0 directory roles (Global Administrator, Privileged
Role Administrator, Privileged Authentication Administrator, Application and
Cloud Application Administrator, Conditional Access Administrator, Hybrid
Identity / Directory Synchronization, Partner Tier support, Domain Name
Administrator), role-assignable groups, service principals / managed identities /
agents holding Tier-0 Graph permissions, the Tier-0 permissions themselves and
the tenant. Right-click a node in the graph or use ★ in a detail panel to add or
remove custom ones; overrides are stored per tenant in the browser.

**Tier-0 Graph permissions:** `RoleManagement.ReadWrite.Directory`,
`AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`,
`DelegatedPermissionGrant.ReadWrite.All`, `RoleEligibilitySchedule.ReadWrite.Directory`,
`RoleAssignmentSchedule.ReadWrite.Directory`, `PrivilegedAccess.ReadWrite.AzureAD`,
`Domain.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`. High-impact
(Tier-1) ones include `Directory.ReadWrite.All`, `Group.ReadWrite.All`,
`User.ReadWrite.All`, `Policy.ReadWrite.ConditionalAccess`, the agent
`*.ReadWrite.All` permissions and others.

## Attack paths

Shortest weighted paths (Dijkstra, reverse from each critical asset) from every
identity to every critical asset, with an exact "via" constraint for analyses
that must use a particular edge kind. A bounded all-paths mode enumerates
alternatives. Predefined analyses: paths to Global Administrator, Privileged Role
Administrator, Conditional Access Administrator, Application Administrator,
Authentication Administrator, privileged applications; paths from guests,
standard users, workload identities, AI agents, external identities; paths
through group ownership, application ownership, credential modification, OAuth
permissions, federation, hybrid identities, password/MFA reset, PIM activation.

### Risk model

Path score = target value (tenant / Tier-0 role 100, Tier-0 permission 95,
Tier-0 workload 90, role-assignable group 80, Tier-1 role 65 …) × path-length
factor × mode factor (eligible 0.85, conditional 0.65) + source modifiers (guest,
external issuer, on-premises, no MFA, excluded from or not covered by Conditional
Access, dormant, secret / federated credential; disabled accounts are discounted).
Severity: Critical ≥ 85, High ≥ 65, Medium ≥ 45, Low ≥ 25, else Informational.

The **Identity Exposure Score** (0–100, higher is worse, graded A–F) weighs
attack paths 35 %, Tier-0 account hygiene 20 %, dangerous permissions 15 %,
findings 20 % and guest reach 10 %. It measures reachable privilege, not
configuration noise.

## Findings

Excessive privilege, dormant privileged account, permanent privileged role,
privileged guest, nested privileged group, privileged group owner, app / service
principal owned by a low-privileged identity, dangerous application and delegated
permissions, tenant-wide risky consent, long-lived / expired / expiring
credentials, no or many app owners, federated credentials and overly broad
federation, orphan apps, role-assignable group exposure, PIM eligibility, Tier-0
accounts synced from AD, privileged identities without MFA, excluded from or not
covered by Conditional Access, legacy authentication not blocked, weak tenant
authorization settings, partner trust, agent identities without owner or with
Tier-0 permissions. Every finding and every attack path carries remediation.

## Coverage: unknown is not the same as none

A missing edge because collection was denied is a different thing from an
edge that does not exist. Every source that did not come back (permission not
consented, endpoint not available, Graph error) is mapped to the edges,
analyses, findings and node sections it blinds, and that caveat travels with
every conclusion:

- **Dashboard** — a coverage line under the score: "N of M sources · score is
  a lower bound · not collected: PIM eligible assignments
  (RoleManagement.Read.Directory) · …".
- **Attack path analyses** — a card whose inputs were not collected shows a
  dashed border, `106?` instead of `106`, and "partial · … not collected"; a
  zero there reads as *unknown*, not *none*.
- **Findings** — one *Informational* `CollectionGap` finding per missing
  source, naming what is invisible and which permission fixes it.
- **Detail panel** — a "Not collected for this object" section, so an empty
  section above it is not mistaken for an empty answer.
- **Report and JSON export** — the coverage table comes first, before any path.

## Explorer, query, export

- **Graph explorer** (Cytoscape): search, type filters, expand, shortest path
  A→B, paths from a node, force / hierarchy / concentric layouts, full screen,
  animated path highlighting; click for the detail panel (overview, roles,
  memberships, effective control, paths from/to, findings, inbound/outbound
  relationships, raw object).
- **Query engine**: plain-English questions are translated to the grammar
  `paths from <selector> to <selector> [via <edge>] [all]`, `nodes <selector>`,
  `who can reach <selector>`, `what can <selector> reach`, `edges <kind>`.
- **Export**: JSON (everything), CSV (findings, paths, identities, applications,
  relationships, critical assets, remediation, collection log) and a
  self-contained HTML report (print for PDF).

## Limits

- Browser-only: a tenant with tens of thousands of groups is collected within a
  cap (members are read for role-holding, owning, CA-referenced and security
  groups first).
- Group member expansion uses direct members per group (nesting is preserved);
  owners come from `$expand` (first 20 per object).
- Agent identity endpoints are beta and only answer in tenants with Entra Agent
  ID.
- The platform infers attack possibilities from effective permissions; it never
  exploits anything.
