# Agent 365 Settings Explained

An interactive walkthrough of the seven Agent 365 admin settings that make up the
control plane. For each setting it shows what it controls, what an animated demo
of it looks like, and — importantly — what it does *not* do. It runs entirely in
the browser as static content, with no sign-in and no tenant connection.

- **File:** `agent-365-settings-explainer.html`
- **Category:** Agent 365
- **Status:** Explainer

---

## What it does

Click any setting to expand its explanation, an animated demonstration and its
gotchas. The seven settings covered are:

- **Policy templates** — four platforms and twelve default protections applied
  by the setup wizard, with a companion **"Verify in Entra — don't trust the
  wizard"** step that shows how permissions, admin consent and the like actually
  land.
- **Agent management rules** — including custom rules.
- **User access** — who can *use* published agents (e.g. specific users or
  groups), shown as User A vs User B in the Copilot portal.
- **Allowed agent types** — e.g. disabling external publishers so a third-party
  agent cannot be added from the store.
- **Sharing** — org-wide vs direct 1:1 sharing.
- **Tags** — applying tags and reading the per-tag agent count in the Tags
  overview.
- **Agent feedback sharing** — routing user reactions to the developer via the
  agent's Monitor section.

Each setting carries inline callouts — a **demo** of the behaviour, plus
**gotcha** and **warn** notes — and an animated SVG walkthrough of how a change
flows through the control plane (create → apply → permissions/admin consent).

---

## Requirements

**No sign-in required.** It runs entirely in the browser and is pure static
content — nothing is fetched from your tenant, and no app registration, token or
permission is involved. The "demo" callouts are illustrations of each setting's
behaviour, not live reads from Microsoft 365.

---

## How to run

1. Open the page over http(s) (e.g. via `blue16.nl`, GitHub Pages, or any static
   host).
2. Click a setting to see what it controls, watch its animated demo, and read
   what it does *not* do.

There is no tenant connection to configure.

---

## Privacy & safety

- **Nothing is collected or sent.** The page is static content rendered locally;
  there is no backend, no authentication and no network calls to a tenant.
- The demonstrations are scripted illustrations, so nothing here touches a real
  Agent 365 configuration.

---

## Limitations

- It is an **explainer, not a scanner** — it teaches how the settings behave and
  does not read or change any real tenant's Agent 365 settings.
- The behaviours shown follow Microsoft's Agent 365 admin model at the time of
  writing; verify against your own tenant, as the product may change.

---

© Blue16 Cybersecurity · Part of the Blue16 Offensive & Defensive Security Tooling suite.
