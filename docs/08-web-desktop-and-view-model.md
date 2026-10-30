# PVOS — Web Desktop & View-Model Protocol (08)

Status: **Draft for review**
Date: 2026-06-21
Depends on: [00 §4.8](00-pvos-architecture.md), [04 (control socket)](04-control-socket-protocol.md), [05 §1 (ui surfaces)](05-app-manifest-and-lifecycle.md)

PVOS owns a **web desktop** — the display surface for app UIs. This doc covers the desktop itself, the two UI mounting modes, and the **server-driven view-model protocol** (the opt-in mode for system apps like IaC).

---

## As built (2026-10-04, D218)

The text below is the design as written (2026-06-21, with later notes); this section lists where the code differs. What the desktop does today is in [`web/README.md`](../web/README.md). `lib.rs` is `crates/pvosd/src/lib.rs`, `web.rs` is `crates/pvosd/src/web.rs`, `App.tsx` is `web/src/App.tsx`.

- **§1.** The front-end is `web/` in this repo; there is no `pvos-web`.
- **§1.1 a socket acts with its own session** (D237, 2026-10-11): `Authed` is honoured only for the token that socket signed in or restored with, as `RenewGrant` already was, so another browser's token is useless on a fresh socket. Consent prompts and the owner-only toasts go to owner sessions only; a member's email-code toast goes to that member's sessions. An app's `/apps/<id>/ui/**` is served only to a session that may use the app (404 otherwise), like its assets and icon. Bounds: 512 web connections per listener, a websocket message ≤ 4 MiB and a frame ≤ 1 MiB.
- **§1.1 sign-in.** Superseded, as the "Shipped since this doc" note before §6 says: sign-in is install-time pairing plus a browser relay (M3.1), with no local-key passphrase mode. Since that note: a member who joined with a passkey signs in with it (D33, D193); every member has a personal forest, and a session is certified in it (D193) by a 7-day grant that is renewed while the session is used (D212); a session is remembered across a reload or a pvosd restart (M9; BACKLOG holds an open report of a reload that showed the sign-in screen again); and the desktop is also served over TLS on `0.0.0.0:7443` (M3.6), not only on localhost.
- **§3 Mode A.** The frame's `src` is always `/apps/<id>/ui/`, and a surface's `entry` is never read (`App.tsx:1837-1841`; `crates/pvos-proto/src/manifest.rs:82`). By the code's own comment a Mode A UI is one self-contained `index.html` (`web.rs:440-453`), at most 8 MiB on a routed install (`crates/pvos-proto/src/control.rs:541-544`). The frame is served with the CSP `connect-src 'self'` (`web.rs:454-456`) and pvosd routes no request to an app's backend, so "its own HTTP/WS to its backend" has no path today. That is read from the code; it was not tested in a browser.
- **§3 the bridge** (`App.tsx:1000-1027`, `:735-740`, `:1846-1857`; `lib.rs:2394-2426`):
  - desktop → iframe: `{pvos:"context", app_id, surface, region}` and `{pvos:"bridge_reply", req_id, ok, payload}`;
  - iframe → desktop: `{pvos:"call_desktop", req_id, op}`, with the ops `notify`, `request_capability`, `discover_services` and `open_app` (owner only). The reply carries the `req_id` the iframe sent (D238; before it, the desktop's own number);
  - the context has no theme or locale, and no `ServiceEvent` or `UiLifecycle` reaches an iframe.
- **§4.2.** Two additions the vocabulary text lacks: `ViewModel.back` (D52: the action the browser's back button maps to) and `text_area.language` (D61: a code editor) (`crates/pvos-proto/src/viewmodel.rs:236-240`, `:337-345`). pvosd refuses a view model over 4 MiB (D209; `lib.rs:174-178`).

---

## 1. The desktop & its transport

`pvos-web` is a browser front-end backed by `pvosd`. Browsers can't open Unix sockets, so the **desktop ↔ `pvosd`** link is a **websocket** (the "separate transport" flagged in doc 04 §8), authenticated as the **owner/user** (the human is signed in via "Sign in with PVFS", doc 10).

The desktop provides the shell chrome: **app launcher, window/surface manager, navigation, notifications, global settings, consent prompts, and the system-health view** (`pvos.monitor`, doc 07).

`pvosd` is the **bridge**: an app's UI messages on its Channel-2 connection (doc 04 §4.4) are relayed to the desktop over the websocket, and user interactions flow back.

### 1.1 Desktop authentication — companion vs local-key (M2)

*(as built: see above — superseded; there is no local-key mode)*

The websocket carries owner/admin authority, so desktop login is a real auth boundary. It works in **both** owner-key modes (doc 09 §3):

- **Companion mode.** The desktop gets a challenge from `pvosd`; the **companion** signs it ("Sign in with PVFS"); `pvosd` verifies → owner session. Strongest; the key never sits on the server.
- **Local-key mode (default install, no companion).** The owner key lives on the server **encrypted at rest under an owner passphrase**. Desktop login prompts for the passphrase, which unlocks the key for the session; the unlocked key signs `pvosd`'s challenge. The key stays in `pvosd` memory only while a session is active and re-locks on logout/idle. *(Decision **D1**: passphrase vs OS-keychain unlock.)*

In both modes the desktop is bound to **localhost** (or the owner's LAN by explicit config) — there is **no anonymous desktop access**. A session is a short-lived token scoped to the owner principal; every *mutation* is still capability-checked, and **sensitive owner actions are re-confirmed** (a passphrase re-prompt in local-key mode, a companion tap in companion mode). So a stolen session can browse but cannot perform gated owner actions without the second factor.

---

## 2. Window / surface model

Each app **UI surface** (declared in the manifest, doc 05 §1) becomes a **window** in the desktop. Lifecycle — open / close / focus — maps to `UiLifecycle` events (doc 04 §4.4). The surface manager owns z-order, focus, and layout; apps don't manage windows directly.

---

## 3. Mode A — Iframe (default, non-system apps)

The app serves its own web UI; the desktop hosts it in a **sandboxed iframe**.

- The app declares `mode: iframe, entry: served` (or a URL). `pvosd` resolves the app's served UI (a local URL, proxied through `pvosd` for auth/isolation) and the desktop opens a window with a **sandboxed** iframe (`sandbox`, CSP).
- **App-UI ↔ app-backend** is the app's own concern (its own HTTP/WS to its backend) — not PVOS's path. *(as built: see above — no such path today)*
- **Desktop integration** is a constrained **`postMessage` bridge** between the iframe and the desktop *(as built: see above — the messages differ)*:

```
desktop → iframe:  Context{app_id, theme, locale}, ServiceEvent, UiLifecycle
iframe → desktop:  CallDesktop{op}        // notify, open-app, request-capability, discover-services
```

The bridge is **mediated** — every `iframe → desktop` op is checked against the app's capabilities (the iframe can't do more than the app backend was granted). The bridge is deliberately small: rich actions go through the app's own backend + Channel 2, not the bridge.

---

## 4. Mode B — Server-driven view-model (opt-in, system apps)

The app sends a **view-model** over Channel 2; the desktop renders it with **native PVOS components**. The app ships **no front-end** and runs no code in the desktop — maximal consistency and isolation.

### 4.1 Flow
```
app → PushViewModel{ surface, view_model }     // doc 04 §4.4
desktop renders with native components
user interacts → UiEvent{ surface, event }     // (push) back to the app
app updates state → PushViewModel{…}           // re-render (diffed)
```

**`pvosd` relays the view model opaquely (D47).** `view_model` is
`serde_json::Value` on the wire types — the daemon routes by surface + actor
and never parses UI vocabulary. A component `pvosd`'s build doesn't know
flows through untouched and the renderer decides what it can draw, so adding
a component no longer requires shipping daemon and apps in lockstep (the
D43 §0b skew class, retired).

**Ordering is guaranteed.** A user's interactions travel down one socket in the
order they happened, and the app SDK delivers them to the app's handler in that
same order, one at a time (`UiEvent` and `UiLifecycle` share the queue, so a
surface's `Open` always precedes the first click on it). Apps may rely on this:
setting a toggle and then pressing the button it configures does what the user
meant. The corollary is that a UI handler holds up the ones behind it, so
handlers stay short and hand long work to their own thread — see the IaC app's
run executor.

**Outbound pushes are asynchronous (D43).** `PushViewModel` from the SDK
enqueues onto a coalescing outbox — only the **latest** frame per
(surface, actor) is kept, and one sender thread drains it. `Ok` means
*queued*, not delivered; a delivery failure is dropped, and the next render
heals the screen. Apps must treat pushes as fire-and-forget — and must
**never do socket I/O while holding their state lock**: render under the
lock, push after releasing it. (The D43 incident: a blocking push under the
state lock, against a peer that had stopped reading, froze the whole app.)

### 4.2 View-model shape
A serializable **component tree** of a fixed vocabulary, with **bound values** and **actions** (action ids that come back as `UiEvent`s):

**Shipped vocabulary** (M3 v1 + M4a additions): `stack, heading, text, field,
button, list, table, form, alert, spinner, log, tabs, toggle, select, text_area,
file_picker, date_time, schedule_at, chart`. Since then: `image, card_grid`
(D38 Media), `segmented, combo` (D42/D44), `diagram` (D248 — boxes
the viewer drags and resizes; releasing one fires its action with
`{id, x, y, w, h}`), and `file_pane` (D286 — one pane of the Files app):

- `segmented` — one row of mutually-exclusive buttons; clicking fires its
  `action` immediately and it never participates in a form submit.
- `combo` — a typeahead text input over option sets too large for a `select`;
  emits its `action` debounced as the user types, and typed text is **not**
  constrained to the options. When `remove_action` is set it becomes a chip
  multi-select: committed values render as ×-removable pills (D44).
- `diagram` — positioned boxes and the lines between them. The viewer drags
  a box to move it and its corner to resize it. Releasing fires `action`
  with `{id, x, y, w, h}` (D248). An edge's `kind` is `runs`, `presents`,
  or `dns`. A server node may carry `chips`, the services drawn inside it;
  an edge may point at a chip. A node labeled like `1 of 3` is where a
  redundant group splits.
- `file_pane` — one pane of a file manager (D286). The app sends the
  place, the path, the names and the commands. The desktop keeps the
  selection, the sort and the name filter, and sends them back with the
  pane's action: `{op, pane, keys}`, plus `name` after a prompt, `place`
  when the place changes, `path` for a breadcrumb, and `from`, `into` and
  `move` for a drop. Drag copies; shift-drag moves. When `confirm` is set
  the desktop asks once for that `confirm_id` and answers `replace` or
  `replace_no` (D287).

Two of those exist because **only the browser knows the owner's timezone** (D32),
so anything calendar-shaped is rendered and computed there and reaches the app as
an epoch instant: `date_time` for an arbitrary moment, and `schedule_at`, which
asks only what a cadence needs — a minute past the hour for hourly, a time for
daily, a weekday plus a time for weekly. "Every day at 02:00" should not make the
owner pick a date. `table.time_columns` is the read-side of the same rule.

`select` may carry an `action`, which fires on change rather than on submit, so a
form can re-render around a choice (the schedule form swaps its time input when
the cadence changes).

`chart` is a small line graph of a recent series — inline SVG, no charting
library, since the desktop ships no third-party runtime. Pass `max` to pin the
vertical scale: an auto-scaled chart of 2% CPU is indistinguishable from one of
90%, which is how a monitor misleads without stating a falsehood.

The `text`, `alert`, and `table` renderers **linkify `https://` tokens**
(D49; tables did it first) — plain text carrying a URL renders it as a
clickable link, so a view model can offer a cross-check link (a TMDB/TVDB
page, say) without needing an anchor component in the vocabulary.

Two outbound-link affordances joined in D58 (Play on Plex), because a
`button` emits an event and **a server round-trip can't open a browser
tab** — an outbound action must BE a link at render time:

- `link` — `{label, url}`, a button-styled anchor
  (`target="_blank" rel="noreferrer"`). **`https://` only**; the
  renderer refuses other schemes.
- **Labeled cell links** — a table cell of exactly `[label](https://…)`
  renders the label as the anchor ("▶ Play" instead of a 40-char URL).
  Whole-cell only, https only; anything else stays literal text. A cell
  convention, not a component — old desktops show the raw text, which is
  the D47 skew story working as intended.

`tabs` may carry `active` to ask the desktop to show a particular tab. It is
honoured **only when the value changes**, so a routine re-push never yanks the
owner off the tab they chose — an app uses it when it has something specific to
show (a notification's "Show me" landing on a failed run's log).
Deferred until a consumer needs them (D10 extend-by-demand): `grid, icon`
(`image` was claimed by D38; `link` by D58; `diagram` by D248;
`file_pane` by D286).

```jsonc
{
  "root": {
    "type": "stack",
    "children": [
      { "type": "heading", "text": "Hosts" },
      { "type": "table",
        "columns": ["name", "status"],
        "rows": [ ["box1", "up"] ],
        "row_keys": ["box1"],             // STABLE identity per row — see below
        "row_action": "open_host",            // → UiEvent{action, row, key}
        "row_buttons": [                      // right-aligned per-row buttons
          { "label": "✕", "action": "delete_host",
            "danger": true, "confirm": "Delete this host?" }
        ] },
      { "type": "field", "id": "password", "label": "SSH password",
        "secret": true },                     // masked, with a reveal toggle
      { "type": "select", "id": "target", "label": "Target",
        "options": ["localhost", "box1"], "value": "localhost" },
      { "type": "button", "label": "Refresh", "action": "refresh" }
    ]
  }
}
```

- **Row actions must carry `row_keys`.** An index is a position in the
  snapshot the user was looking at; by the time the event arrives the
  collection may have changed (a concurrent push, a second click while a
  confirm dialog was up, another signed-in tab), so resolving by index acts on
  the *wrong* record — for a delete button, it destroys the wrong one. The
  desktop sends `{row, key}` and appends the key to any `confirm` text; the app
  resolves by key and reports a vanished target. (Found in the M4a review,
  2026-07-25.)
- **`field.secret`** renders masked with a reveal toggle and opts out of the
  browser's password manager — these secrets belong in `pvos.keychain`.
- **Vocabulary is fixed but extensible** over time; apps limited to it (the tradeoff for consistency). Custom/rich UIs use Mode A instead.
- **Updates are diffed** — the app pushes new view-models; the desktop reconciles (no full reload). Since D43, intermediate frames may be **coalesced away** before delivery (latest per surface+actor wins) — a push is a statement of current state, never a step in a sequence the desktop must see.
- **Streaming / append data needs a dedicated primitive.** Diffing a full view-model is a poor fit for high-frequency append streams (e.g. a live run log — surfaced by the IaC app's own doc 04, §8 F2: HomeLab `services/homelab-app/docs/04-iac-as-pvos-app.md`). The vocabulary therefore includes a **`log` / append component** that takes incremental appends rather than full re-pushes; alternatively, an app may use **per-surface modes** (most surfaces view-model, the streaming pane an iframe). *(Refinement from M4.)*
- **Theming/consistency** are the desktop's, automatically.

This is the mode intended for **IaC** (and possibly MediaForest): operational dashboards, tables, forms — exactly what a fixed component set serves well.

---

## 5. Security

- **Iframe apps** are sandboxed (iframe `sandbox` + CSP); the `postMessage` bridge is capability-checked; an app's UI can never exceed the app's grants.
- **View-model apps** run **no code** in the desktop — only data crosses, so the attack surface is the renderer.
- The **desktop is a privileged surface** authenticated as the owner/user; consent prompts and admin live here.
- Per-app UI isolation: one app's window cannot read another's.
- **The shell has its own CSP** (D204): script only from pvosd's origin (no
  inline script, no `eval`), connections only to pvosd and the companion's
  loopback agent (plus the origin `/companion.json` names), no framing of
  the shell, `nosniff`, `Referrer-Policy: same-origin`.
- **A Mode A UI is verified at each launch** (D204): the request for the
  app's `index.html` checks the live `/apps/<id>/ui` subtree against
  `integrity.ui_root` again; that launch's other assets use the result.

---

> **Shipped since this doc (M3.1 / M3.5 / M3.7):**
> - **Desktop sign-in is now install-time pairing + a browser relay** (M3.1),
>   not the companion-signs-the-challenge-directly / local-key model in §1.1.
>   `pvosd` pairs with a member's companion once at install, then relays signed
>   sign-in/consent envelopes down the ws → page → companion loopback (a
>   signed dumb-pipe, Origin-bound, with a 6-digit match code). Sessions carry
>   `{member, role}`. See [milestones/M3.1-companion-pairing.md](milestones/M3.1-companion-pairing.md).
> - **Iframe serving is resolved (open-question 2):** PVOS serves the app's
>   **static assets**, as a sandboxed opaque-origin iframe (M3.5) whose bytes
>   are **forest-resident** (M3.7) — `/apps/<id>/ui/`, `integrity.ui_root`-verified.

## 6. Open questions

1. ~~**View-model vocabulary scope**~~ → **Settled in practice:** v1 shipped
   in M3, and M4a added `tabs`/`select`/`text_area` + table row buttons on
   demand (D10). The extension path — a real consumer asks, the component
   lands in `pvos-proto` + the renderer together — is now proven; latest
   additions are `image`/`card_grid` (D38) and `segmented`/`combo`
   (D42/D44, Browse's filter row and chip multi-select); `grid`, `icon`
   remain unclaimed.
2. ~~**Iframe UI serving**~~ → **Resolved:** static assets, forest-resident (M3.5 + M3.7 above).
3. **Offline / native shells** — the same desktop later as a native app (doc 00 §11); the websocket transport generalizes.
4. **Cross-app embedded views** — one app embedding another's surface (composition) — defer.
