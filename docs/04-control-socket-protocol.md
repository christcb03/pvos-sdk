# PVOS — Control-Socket Protocol (Channel 2) (04)

Status: **Draft for review**
Date: 2026-06-21
Depends on: [00 §4.7–4.8](00-pvos-architecture.md), [02 (delegation/effectiveness)](02-delegation-and-revocation.md), [03 (pvos-core)](03-pvos-core-and-types.md)
Defines: the message set that lives in `pvos-proto`.

This is **Channel 2** — the **app-backend ↔ `pvosd`** control socket. It carries everything PVOS brokers; it does **not** carry storage (that is Channel 1, direct to `pvfsd`).

---

## As built (2026-10-04, D218)

The text below is the design as written (2026-06-21, with later dated notes); this section lists where the code differs. The message set as built is `crates/pvos-proto/src/control.rs` (`ClientMsg`, `ServerMsg`); `lib.rs` below is `crates/pvosd/src/lib.rs`.

- **§3 attach.** The `Auth` must arrive within the challenge's 30 s (D237): the socket's read timeout is set to the challenge TTL until attach, so a peer that connects and says nothing is dropped (`pvos.control.auth_refused`, reason `auth_timeout`) instead of holding a thread; it is cleared once attached. The challenge field is `expiry_ms`, not `expiry`. The context also carries `grants_root` (the app's own `/apps/<id>/grants` node) and, on the owner's session only, `pvosd_build` (D205) (`control.rs:47-63`, `:318-322`).
- **§4.1.** `Ping`/`Pong`, the `Lifecycle{StopRequested|Shutdown}` push and `Bye` were not built. What exists instead is the `ParkHint` push (D45, `control.rs:389-393`). Stopping an app is kill-and-reap (`lib.rs:902-913`); a stopping pvosd sends its apps SIGTERM and kills what is left after 5 s (D205, `lib.rs:404-406`, `:5284-5310`).
- **§4.2.** `RequestCapability{capability, reason}` gets no immediate reply; when the consent resolves the app is pushed `Granted{grant_id}`, or `Error` with code `denied` or `expired` (`control.rs:148-155`; `lib.rs:2159-2184`, `:2247-2270`, `:6256-6265`). There is no `Denied` message. `Delegate` and `RevokeGrant` do not exist: the app sends `ValidateDelegation{capability, depth}` → `Ack`, signs and appends the grant (or revoke) record into its own `/apps/<id>/grants` over Channel 1, then sends `NotifyGrantsChanged` (`control.rs:81-93`; `crates/pvos-sdk/src/lib.rs:893-983`).
- **§4.3.** `CallService` also carries `provider`, and its `version` is accepted and ignored (`control.rs:104-114`; `lib.rs:6074-6080`). `IncomingServiceCall` also carries `service`; the provider answers with `ServiceReply{call_id, outcome}`. A provider emits with `EmitEvent{topic, payload}` (`control.rs:116-124`, `:350-358`).
- **§4.4.** `RegisterUiSurface` and `UnmountUiSurface` do not exist: an app's surfaces come from its manifest (`ui.surfaces`). The pushes to the app are `UiEvent{surface, action, payload, actor?}` and `UiLifecycle{surface, phase: open|close|focus, actor?}`. `AppendLog{surface, component_id, lines}` appends to a `log` component without a re-push (`control.rs:126-147`, `:365-388`).
- **§4.5.** The app ops are `AdminInstall` (legacy), `AdminInstallApp` (with `take_over`, D204), `AdminStartApp`, `AdminStopApp` and `AdminList`; grants are `AdminGrant` and `AdminRevoke`. There is no uninstall op and no `Inspect`: `pvos inspect` filters the `AdminList` reply (`crates/pvos-cli/src/main.rs:1319-1345`). Built and not listed in §4.5: invites (`AdminInviteCreate`, `AdminInviteList`, `AdminInviteRevoke`), `AdminShare` / `AdminUnshare`, the seven `AdminMember…` ops, sessions (`AdminSessionList`, `AdminSessionRevoke`), `AdminPair`, the owner's notifications (`AdminNotifyList`, `AdminNotifyDismiss`) and `AdminMailSetup` (`control.rs:157-311`).
- **§5 tolerant decode.** D50 narrowed D47: only an unknown message tag is skipped; a known tag whose body will not decode is fatal (`lib.rs:5918-5947`).
- **§9.** Nothing is negotiated or compared at attach: the context reports `api_version` and the SDK does not check it (`crates/pvos-sdk/src/lib.rs:388-420`). The checks that exist are `pvos install` refusing a manifest with another `api_version` (`crates/pvos-cli/src/main.rs:890-895`) and the launch gate on the manifest's `requires` floors (D63, `lib.rs:849-860`).

---

## 1. Purpose & scope

Channel 2 is how a running app reaches PVOS for: **capability calls**, the **service registry** (publish / discover / call), **UI mounting**, **events**, **lifecycle**, and **just-in-time capability requests**. It mirrors PVFS's daemon protocol (doc 07) in shape, so the two systems feel the same.

- **Parties:** an **app backend** (a process holding the app's key) and **`pvosd`**. The **web desktop (browser) ↔ `pvosd`** link is a *separate* transport (§8), designed with the web desktop; `pvosd` bridges UI messages between the two.
- **Storage is never here.** The app's `HostContext` hands it the `pvfsd` socket + its key + region root; storage I/O goes direct to `pvfsd`, ACL-enforced, PVOS out of the path.

---

## 2. Transport & framing

- **Unix-domain socket**, at a conventional discoverable path (mirrors `pvfsd`). *(Bare-metal PVOS may change the transport later; the message set is transport-agnostic.)*
- **Length-prefixed JSON frames:** `u32 length (LE) || JSON body` — same as PVFS doc 07. JSON keeps it debuggable and lets non-Rust apps speak it.
- **Long-lived, multiplexed, async.** Requests carry a `req_id`; responses echo it. `pvosd` can **push** unsolicited messages (events, inbound service calls) with their own ids. One connection per running app.

---

## 3. Attach (handshake)

```
app ──connect──▶ pvosd
pvosd ──▶ Challenge { nonce, instance_id, expiry }
app   ──▶ Auth { pubkey, sig = sign(digest(nonce, instance_id, expiry)) }
pvosd ──▶ Ready { context }    // or Error
```

- `pvosd` verifies the key is a **registered, authorized, non-revoked app** (or the **owner/admin**, §4.5). There is **no anonymous tier** on the control socket — unlike `pvfsd`'s public read, only installed apps and the owner connect here.
- `context` (the `HostContext`, doc 03 §6.3): `{ app_id, region_root: NodeId, pvfsd_socket: path, capabilities: [Capability], api_version }`.

---

## 4. Message taxonomy

Request/response unless marked **(push)**. *(as built: see above — several messages in §4.1, §4.2, §4.4 and §4.5 were not built or were built under other names)*

### 4.1 Session & lifecycle
- `GetContext → Context` — re-fetch the HostContext.
- `Ping → Pong` — keepalive.
- **(push)** `Lifecycle { StopRequested | Shutdown }` — PVOS asks the app to wind down / is shutting down.
- `Bye` — clean disconnect.

### 4.2 Capabilities
- `ListCapabilities → [Capability]` — this app's currently-effective capabilities.
- `RequestCapability { capability } → Granted { grant_id } | Denied { reason }` — the JIT consent path (owner-gated for privileged kinds, doc 00 §4.4).
- `Delegate { subject, capability, depth?, expiry? } → GrantId | Denied { reason }` *(as built: see above)* — issue a **narrowed** capability to another app (doc 00 §4.6). `pvosd` validates attenuation (`covers`) + the caller's re-delegation depth, then performs the **member-signed write into the caller's own `/apps/<id>/grants`** region (the caller signs; doc 02 §2.1). `RevokeGrant { grant_id }` revokes one the caller issued.
- **(push)** `CapabilityChanged { granted | revoked, capability }` — the broker recomputed effectiveness (doc 02 §4).

### 4.3 Services (the behavior plane)
- `PublishService { decl } / UnpublishService { name }` — advertise / withdraw an ability this app offers.
- `DiscoverServices { query? } → [ServiceInfo { name, provider, versions, interface_ref }]` — find PVOS's and other apps' services (versions support the negotiated-upgrade model, doc 00 §6).
- `CallService { service, method, args, version? } → Result | Error` — `pvosd` **authorizes** (caller holds the capability to call that service) then **routes** to the provider.
- **(push)** `IncomingServiceCall { call_id, from, method, args }` → provider replies `ServiceReply { call_id, result }`.
- `Subscribe { topic } / Unsubscribe`; **(push)** `ServiceEvent { topic, payload }`.

> **Unification:** built-in services (keychain, scheduler, monitor) are reached *exactly this way* — they are services whose provider is PVOS. So "calling a non-storage capability" **is** "calling a service": the **capability is the permission**, `CallService` is the **action**, and the broker checks the former before routing the latter. §4.2 and §4.3 are one mechanism.

### 4.4 UI
- `RegisterUiSurface { name, mode }` where `mode ∈ { Iframe { url | served }, ViewModel }` (doc 00 §4.8).
  - **Iframe:** the app names where its UI is served; `pvosd` tells the web desktop to open a window with that iframe. User interaction stays app-UI ↔ app-backend; a `postMessage` bridge gives the iframe access to desktop services.
  - **ViewModel:** `PushViewModel { surface, view_model, actor? }` (app → desktop, via `pvosd`); **(push)** `UiEvent { surface, event }` (user interactions relayed back). The desktop renders with native PVOS components. `actor` (D39): `None` broadcasts to every session with the surface open; `Some(actor)` renders for one session — per-viewer navigation on a shared surface. Delivery is **at-most-latest, async** (D43): the SDK coalesces pushes (latest frame per surface+actor wins), `Ok` means queued not delivered, and a dropped frame is healed by the next render. **`view_model` is opaque to `pvosd`** (D47): both it and `SurfaceUpdate.view_model` are `serde_json::Value` — `pvosd` routes by surface + actor and never parses UI vocabulary, so a component unknown to its build flows through untouched (wire bytes unchanged; the web renderer, which always consumed plain JSON, decides what it can draw).
- `UnmountUiSurface { name }`; **(push)** `UiLifecycle { opened | closed | focused }`.

### 4.5 Admin (owner/CLI principal only)
- `InstallApp / UninstallApp / StartApp / StopApp / ListApps`. *(as built: see above — the op names differ and there is no uninstall)*
  - **Install is one op that does everything (D195):** `AdminInstallApp`
    carries the manifest and the app's `ui/` files; `pvosd` imports them
    into `/apps/<id>/ui`, pins `integrity.ui_root` (only from that import)
    and answers `AppInstalled` with the pin and its pvfsd's protocol. It is
    the same install the offline CLI runs (`Pvos::install_app_bundle`).
  - A pvosd lists its newer ops in the `AdminList` reply's `daemon_ops`. An
    older one skips an unknown op without answering, so clients check
    `daemon_ops` before sending one.
  - The original `AdminInstall` (no `ui/`) stays for older CLIs, and refuses
    an app with an iframe surface.
- `Grant / Revoke` — the owner issuing or cutting capabilities.
- `Inspect` — the authority graph (doc 02 §9), published services, mounted surfaces.

---

## 5. Routing & correlation

`pvosd` is the **broker/router** in the middle. A cross-app service call flows: **app A → `pvosd` (authorize) → provider B** via `IncomingServiceCall` → B replies → `pvosd` → A. Every in-flight request/call carries an id (`req_id` / `call_id`) so responses match up; the connection is fully async and multiplexed. `pvosd` holds one live connection per running app and routes between them.

**Connection hygiene (D43).** A per-app serve loop that exits — error, EOF, or panic (caught) — must on **every** path: log the exit reason, deregister the connection, and `shutdown(Both)` the socket before joining the writer, so a peer blocked mid-send errors immediately instead of waiting on a buffer nobody will drain. The D43 incident was exactly this contract skipped: an errored reader `?`-returned past cleanup, leaving the socket open-but-unread, and the app's next push blocked forever.

**Tolerant decode (D47).** Both readers — `pvosd`'s app-conn loop and the SDK's `reader_loop` — first parse a frame as JSON, then decode the typed message. Framing/JSON corruption stays **fatal** (the stream is broken); an unknown typed message merely logs "unknown message (version skew?) — skipped" and continues. A new message variant reaching an old peer degrades to a log line, never a dead connection.

---

## 6. Security

- The **connection's principal is the authenticated app key** — a message can never impersonate another app.
- Every brokered action (capability call, service call, UI mount) is **capability-checked against the effective set** (doc 02 §4) at call time; revocation/expiry take effect immediately.
- **Admin ops** require the owner/admin principal; privileged/system-only operations are gated (doc 00 §3.2/§4.4).
- **No anonymous tier** — only installed, authorized apps and the owner reach the control socket.

---

## 7. Milestone 1 subset

M1 is storage-only, so the control socket is **minimal**: just **§3 Attach** + **§4.1 `GetContext`**. That delivers the `HostContext`, after which the app uses Channel 1 (direct `pvfsd`) for everything M1 does. Capabilities/services/UI/events (§4.2–4.4) are *designed here* but built at **M2** (services/capabilities) and **M3** (UI). M1's "no non-storage capability" is demonstrated as **absence of a handle** (the catalog isn't wired), consistent with doc 03 §8.1.

---

## 8. Boundaries & related transports

- **Storage** stays Channel 1 (direct `pvfsd`) — never traverses Channel 2.
- **Web desktop ↔ `pvosd`** is a **separate, browser-friendly transport** (websocket/HTTP — browsers can't open Unix sockets), specified with the web desktop. `pvosd` **bridges** the §4.4 UI messages between an app's control connection and the desktop over that transport. This doc covers only **app-backend ↔ `pvosd`**.

---

## 9. The `pvos-proto` crate & versioning

All message and type definitions here live in **`pvos-proto`**, depended on by both `pvosd` (server) and `pvos-sdk` (client). The connection negotiates an **`api_version`** at attach; a mismatch fails loudly (never a silent downgrade of trust) *(as built: see above — nothing is compared at attach)*. Additive message types bump a minor version; breaking changes bump major and are refused across the boundary.

**Known gap (D43 §0b) — CLOSED by D47:** `api_version` does not cover additive view-model *component variants*, and an old `pvosd` used to fail the frame decode and kill the app's connection mid-push. D47 retired the class two ways: `pvosd` relays view models **opaquely** (`serde_json::Value` passthrough — it never parses UI vocabulary), and both connection readers use **tolerant decode** (framing fatal, unknown typed messages logged + skipped). Additive component variants are now harmless and lockstep releases are no longer mandatory — D47 was the last release that had to ship everything together. The release pipeline still rebuilds the daemons it publishes (the deploy-honesty half of the same incident).

---

## 10. Open questions

1. **Backpressure / flow control** for high-volume events or streamed results. *Partially resolved (D43) for view pushes:* the SDK's coalescing outbox makes pushes at-most-latest and droppable, so a slow desktop can't stall an app. Events and streamed results remain open.
2. **Large / bulk payloads (resolved in principle).** Bulk bytes (e.g. media streams — MediaForest MF1) **never** ride Channel 2: pass a **`pvfs` node reference** and read it directly via the now-shipped PVFS **raw data plane** (P2-F). The control plane stays light.
3. **The iframe `postMessage` bridge** — specify its surface now or with the web desktop (leaning: with the web desktop).
4. **`api_version` compatibility policy** — exact negotiation + deprecation rules. *Less urgent since D47:* additive skew (new components, new message variants) now degrades to a logged skip instead of a dead connection, so the policy question is about deliberate breaking changes only.
5. **Service-call timeouts & failure semantics** — provider crash mid-call returns a typed error (doc 06 §6); long-running calls use the **async job** shape (doc 06 §6.1). Remaining: slow-provider timeout tuning.
