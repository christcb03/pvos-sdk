# PVOS — App Manifest & Lifecycle (05)

Status: **Draft for review**
Date: 2026-06-21
Depends on: [00 §3](00-pvos-architecture.md), [02](02-delegation-and-revocation.md), [03](03-pvos-core-and-types.md), [04](04-control-socket-protocol.md)

Defines what an app *declares* (the manifest) and how PVOS *runs* it (the lifecycle).

---

## As built (2026-10-04, D218)

The text below is the design as written (2026-06-21, with later "Shipped" notes); this section lists where the code differs. `lib.rs` is `crates/pvosd/src/lib.rs`, `registry.rs` is `crates/pvos-core/src/registry.rs`, `cli` is `crates/pvos-cli/src/main.rs`.

- **§1 fields.** `icon` is a path inside the app's own `ui/` bundle since D209, not a `pvfs://` ref (`crates/pvos-proto/src/manifest.rs:122-128`). The manifest also has `admin_only` (D18; `manifest.rs:143-148`), which the example lacks. `tier` and `residency` are parsed and then read by nothing in pvosd, pvos-core, the SDK or the CLI: "system ⇒ owner-gated" and isolated residency have no code behind them. The property that is enforced is `admin_only` — such an app is never shared below admin (`lib.rs:2663-2676`).
- **§1 capabilities, §3 step 4.** The manifest's `capabilities` are printed at the install consent and read nowhere else (`cli:961-977`). Install writes one grant: `rw`, re-delegation depth 1, on the app's `data` region (`crates/pvos-core/src/lib.rs:372-390`). Service capabilities come from `pvos grant --app <id> --service <name> [--entries …]` (`cli:1058-1122`; the installer runs it for the Media, Torrents and IaC apps, `deploy/ansible/pvos.yml:1139`, `:1264`, `:1354`) or from a runtime consent.
- **§1.1.** The PVFS wire protocol is 16 (PVFS `crates/pvfs-proto/src/lib.rs:60`), not 3. 3 is the floor `examples/bt/manifest.json` declares.
- **§2.** The lifecycle states are not in the code. What is surfaced per app is `running: bool` (`crates/pvos-proto/src/control.rs:584-588`).
- **§3 install.** The layout is `/apps/<id>/{key, manifest, ui/, data, grants}` — no `code`, no `state` (`registry.rs:25-31`, `:110-128`). The app's private key is `<app-dir>/device.key`.
- **§4 start.** The launch passes two environment variables, `PVOS_CONTROL_SOCKET` and `PVOS_APP_DIR` (`lib.rs:869-871`); the app loads its key from that directory and learns its id from the attach context.
- **§5 update.** There is no update op. A reinstall replaces the key and manifest records in place (`registry.rs:130-183`) and imports and pins `ui/` again (`crates/pvos-core/src/lib.rs:443-487`). There is no capability diff, no versioned `code` node and no rollback. The two "Shipped" notes in §5 (D34, D204) are as built.
- **§6 uninstall.** Not built: there is no CLI command and no control op.
- **§7 stop, shutdown.** Stop is kill-and-reap, with no `Lifecycle{StopRequested}` and no grace period (`lib.rs:902-913`). A stopping pvosd sends every app SIGTERM, waits 5 s and kills what is left (D205; `lib.rs:404-406`, `:5284-5310`).
- **§8 key rotation.** A reinstall whose app dir holds a new `device.key` replaces the key record. Since PVOS D253 (2026-10-19) the old key is **retired** first: written to `/apps/<id>/retired`, its PVFS membership revoked, its `rw` on the grants node and every storage ACL it was given cleared, so a copy of the old key reads and writes nothing. An interrupted retirement is finished at the next boot. A retired key is never admitted again: reinstalling with it is refused, and the app needs a new key. Delegations the old key wrote stay valid (the log is judged by place). Before D253 the old key kept its membership and those ACLs.

---

## 1. The manifest

A signed JSON document stored at `/apps/<id>/manifest`. It is the app's contract with PVOS.

```jsonc
{
  "id": "com.example.hello",        // stable, reverse-DNS to avoid collisions
  "version": "1.2.0",               // semver of the app
  "api_version": 1,                 // Shell↔App / Channel-2 contract version it speaks
  "requires": {                     // D63: minimum daemon protocol versions (see §1.1); omit = no floor
    "pvfs_proto": 3,                //   needs PVFS wire protocol ≥ 3 (the ingest ops)
    "pvos_api": 1                   //   needs Channel-2 contract ≥ 1
  },
  "display_name": "Hello",
  "publisher": "key:<pubkey>",      // signer of the package (store: must be open-source & inspectable)
  "description": "…",
  "icon": "pvfs://…",               // optional, a node ref

  "tier": "user",                   // user | system   (system ⇒ owner-gated, privileged §00.3.2)
  "residency": "integrated",        // integrated | { isolated: { forest: "<ref>" } }   (§00.3.5)

  "capabilities": {
    "required": [ { "kind": "storage", "scope_hint": "own-region", "reason": "store its data" } ],
    "optional": [ { "kind": "service", "scope_hint": "pvos.keychain", "reason": "DB access" } ]
  },

  "node_types": ["hello.note"],     // the type namespace this app will create (prefixed by id)

  "services_provided": [
    { "name": "greeter", "version": "1.0.0", "interface": "pvfs://…schema", "methods": ["greet"] }
  ],
  "services_consumed": [
    { "name": "pvos.keychain", "version": "^1", "optional": false }
  ],

  "ui": {
    "surfaces": [
      { "name": "main", "mode": "iframe", "entry": "served" },     // or mode:"viewmodel"
      { "name": "settings", "mode": "viewmodel" }
    ]
  },
  "headless": false,

  "member_actions": [               // D259: what the owner may let a member do in this app
    { "name": "acknowledge", "description": "Acknowledge an alert" }
  ],

  "runtime": { "kind": "native", "entrypoint": "./hello" },  // native process now; wasm later
  "integrity": { "sig": "<signature over manifest+code>" }
}
```

Notes:
- **`scope_hint`** is resolved to a concrete `Scope` at grant time (e.g. `own-region` → `/apps/<id>/data`). Least-authority default: an app's storage scope is its own region unless the owner grants more.
- **`tier: system`** apps are owner-gated and may request privileged capabilities and the right to replace built-in services (doc 07).
- **`services_consumed`** version constraints drive the negotiated-upgrade binding (doc 06, doc 00 §6).
- **`member_actions`** (D259) are checked at install (names `a-z 0-9 _ - .`, 1–32 characters, starting with a letter; at most 32; descriptions 1–120 characters). A grant names the app and the action and lives in the member's signed pairing record; `pvos.actors` answers it only for the app that declares it.
- **`integrity.sig`** ties manifest to code; the public store additionally requires open-source, inspectable code (doc 00 §10).

> **Shipped (M3.7):** `integrity` also carries **`ui_root`** — the content
> digest of the app's `ui/` subtree. At install `pvos` imports the app's `ui/`
> into the forest at `/apps/<id>/ui/` (signed, content-addressed nodes) and
> pins `ui_root`; `pvosd` serves assets from PVFS after re-checking that digest
> (no host-disk trust). `integrity.sig` (a separate publisher signature) stays
> optional until publisher keys land — today the owner-signed forest write is
> the guarantee. See [milestones/M3.7-forest-resident-apps.md](milestones/M3.7-forest-resident-apps.md).
> Native `entrypoint` backends keep a host path until the wasm tier (D13).

### 1.1 Version requirements (`requires`) — D63

An app sits on two daemons, and declares the **minimum protocol version**
of each it can run against. Both are **monotonic integers**: the app runs
on `installed ≥ min`. Omit a field (or set `0`) for "no floor".

| Field | Floor against | Source of truth |
|---|---|---|
| `pvfs_proto` | PVFS wire protocol — bumps with every additive wire op | `pvfs_proto::PROTO_VERSION` (phrasevault [VERSIONING.md](../../phrasevault-repo/VERSIONING.md)) |
| `pvos_api` | Channel-2 shell↔app contract | `pvos_proto::API_VERSION` |

**Current daemon versions:** `pvfs_proto = 16` *(D218, 2026-10-04: was
written as 3 — the version that brought the P10 ingest ops, ranged `Cat`
and partial paths; anything below 3 lacks the ingest seam, and 3 is still
the floor the Torrents app declares)* · `pvos_api = 1`.

**Two checks, one authoritative:**

- **At launch (the gate)** — `pvosd` reads the *live* pvfsd's version via
  `Client::daemon_proto()` and its own `API_VERSION`, and if either is
  below the manifest floor it **refuses to spawn** with a clear
  `incompatible:` message the desktop renders as an error card — it never
  spawns the app into a panic. This is authoritative because the daemon
  version is a runtime fact (a server can lag or be upgraded).
- **At install (a warning)** — `pvos install` connects to the target
  pvfsd and warns (`pvfs-proto-too-old`) if it is below the floor, so the
  operator can update the daemon before first launch. The ansible deploy
  turns that warning into a hard stop rather than shipping an app that
  would refuse to start; it does **not** update the daemon as a side
  effect (that restarts the forest and touches every app — a deliberate
  operator step).

Deliberately **not** semver strings and **not** a named-capability
registry: a monotonic number answers "version or later" exactly. Full
rationale + the incident that motivated it:
[milestones/D63-version-handshake.md](milestones/D63-version-handshake.md).

Deserialization is serde-defaulted, so **manifests without `requires`
keep working** (floor 0 = the baseline every daemon has always met).

---

## 2. Lifecycle states

```
        install                start              stop
(none) ───────▶ Registered ───────▶ Running ───────▶ Stopped ──┐
                    ▲   │              │  ▲                      │
              update│   └──────────────┘  └──────start──────────┘
                    │        (crash → supervised restart)
                    │
                 uninstall ───────▶ (removed)
```

`Registered` (installed, not running) · `Starting` · `Running` · `Stopping` · `Stopped` · `Updating` · `Failed`. *(as built: see above — only `running` exists)*

---

## 3. Install

1. **Validate** the manifest; check `api_version` compatibility (refuse on mismatch), and **warn** if the target pvfsd is below `requires.pvfs_proto` (§1.1 — a friendly early warning; the launch gate is authoritative).
2. **Generate the app keypair**; **authorize** its pubkey as a forest member (`authorize_member`, owner-signed). Persist the private key as a per-app key file (M1) / companion-managed later.
3. **Register** under `/apps/<id>`: `manifest`, `code` (ref — local path M1, content-addressed package later), `data` (region root), `state`.
4. **Consent** (hybrid, doc 00 §4.4): show the user the `required` capabilities + reasons; owner-gate any `system`/privileged ones. On approval, `broker.grant(owner, App(id), cap)` for each.
5. **Project** storage grants to PVFS ACLs (`set_acl` on the region for the app's `key:`). App is now **Registered**.

A non-interactive `--auto-approve` policy path exists for tests (gated, never silently on in prod).

---

## 4. Start

0. **Version gate (D63, §1.1):** before spawning, `pvosd` checks the live
   daemons against `requires` — `pvfs_proto` via `Client::daemon_proto()`,
   `pvos_api` against `API_VERSION`. Below either floor it refuses with an
   `incompatible:` message (surfaced to the desktop as an error card) and
   the app stays `Registered` — it is never spawned into a panic.
1. Build the `HostContext` from the app's currently-effective grants (doc 02 §4).
2. **Launch** the app process (child of `pvosd`), handing it — via env/args — the **control-socket path**, its **key file**, and its **app id**.
3. The app **attaches** over Channel 2 (handshake, doc 04 §3), `GetContext`, and runs.
4. `pvosd` **supervises** the child: tracks it, reaps and respawns on the next start/open (see §7 for the shipped crash behavior), reports liveness to the health service (doc 07).

---

## 5. Update

*(as built: see above — an update is a reinstall; steps 1–4 and the rollback are design only)*

1. Fetch the new version; validate; check `api_version`.
2. **Diff capability requests** — any *new* required capability needs fresh consent; removed ones are revoked.
3. **Supersede** `code` + `manifest` (new versioned nodes, link re-homed — doc 00 §6 mechanics); history retained for rollback.
4. **Restart** the app. Consumed-service bindings re-evaluate via the negotiated-upgrade flow (doc 06).

Rollback = re-home `code`/`manifest` to the prior version.

> **Shipped (D34):** update-by-reinstall means the forest copy — the one
> `pvosd` enforces — can silently lag the install dir when a *schema* addition
> lands: every post-M1 field is serde-defaulted, so a pre-addition install
> keeps its old copy and the new field quietly takes its default (a pre-D18
> install of an admin-only app was shareable until reinstalled). `pvos apps
> check` diffs every installed app's forest manifest against
> `<install-dir>/manifest.json` (the install-time entrypoint/`ui_root`
> rewrites normalized out) and exits non-zero on drift; the pipeline's report
> stage runs it against the live system after every run. See
> [milestones/D34-manifest-drift-check.md](milestones/D34-manifest-drift-check.md).

> **Shipped (D204): a reinstall under another app's name asks.** An install
> over an existing id is an upgrade when it keeps the installed manifest's
> `publisher` (both set) or, when either has none, its `display_name`; a key
> rotation changes neither. Anything else is a **takeover** — the package
> would inherit the old app's data region, grants and secrets — and
> `pvos-core` refuses it unless the caller marks it. `pvos install` shows who
> holds the id and who asks for it, and asks at a terminal; a script passes
> `--take-over`. pvosd refuses an unmarked takeover on both install ops (the
> pre-D195 `admin_install` has no mark, so it refuses every takeover). Until
> packages carry publisher keys (D35) the built-in apps set no `publisher`,
> so **renaming one needs `--take-over` once**, and a package that copies an
> app's name passes as an upgrade — the rule catches accidents, not an
> impostor. See
> [milestones/D204-harden-before-public.md](milestones/D204-harden-before-public.md) §5.

---

## 6. Uninstall

*(as built: see above — uninstall is not built)*

1. **Stop** the app (§7).
2. **Revoke** all grants held *by* and issued *by* the app; cascade (doc 02 §5). Clear its PVFS ACLs.
3. **Revoke the app key** (`DeviceRevoked`, owner-signed) — its tags/grants go inert (PVFS doc 10 §9.2).
4. **Data:** by default retain the app's region (so a reinstall can recover it) unless the user chooses to purge; purge = remove the region links, letting PVFS orphan-GC reclaim the nodes.
5. Remove the `/apps/<id>` registration.

---

## 7. Stop & supervision

- **Stop:** push `Lifecycle{StopRequested}` (doc 04 §4.1), allow a grace period, then terminate; mark `Stopped`. *(as built: see above — no such push; stop is a kill)*
- **Crash:** *as designed:* supervised restart with backoff; repeated failures → `Failed` + an alert. *As shipped:* the janitor **reaps** the exited child and **logs** it (`app '<id>' exited (<status>)`); respawn happens on the **next start/open** (`start_app` reaps-then-respawns) — no backoff, no `Failed` state yet. *(D45 widened "next demand":* `fire_due` finding a scheduled job's owner unconnected now **starts the app** and delivers on the next tick — a force-closed app no longer loses its nightly.*)* The SDK leans on exactly this: after six consecutive dead-air requests it **`exit(70)`s loudly** so the stale process dies rather than serving a dead connection, and the next open brings up a fresh one. That self-heal contract works *because* supervision respawns on demand — change one, revisit the other.
- **Parking (D45):** the janitor **parks** a supervised app that has been background (no desktop session with one of its surfaces open) for 15 minutes: a `ParkHint` goes down, the SDK runs the app's `on_park` (decline while real work is in flight; demand-driven apps park by default), and on accept the app exits 0 and is reaped. Parking returns all memory to the system; the next open or scheduled fire brings it back. Background apps are also reniced +10, restored to 0 on window-open.
- **Shutdown:** on `pvosd` shutdown, `Lifecycle{Shutdown}` to all apps, drain, stop. *(as built: see above — SIGTERM, 5 s, then kill)*
- **Hangup:** an app **exits when its control session closes** — its `main`
  parks on `AppConn::wait_closed()`, not on a sleep loop. An app that outlives
  its session is a ghost: still holding its forest subtree, still on its
  schedules, invisible to `pvosd`. Two writers on one subtree is a correctness
  hazard, so this is a contract, not a nicety.

---

## 8. App key lifecycle

Generated at install, authorized as a member, used by the app to sign its own writes and to authenticate on Channel 2. **Rotation:** authorize a new key, re-issue the app's grants/tags under it, revoke the old (its old tags orphan — PVFS doc 10 §9.2). Companion-managed keys (later) make this smoother.

---

## 9. Open questions

1. **App id scheme** — enforced reverse-DNS vs free slug; uniqueness + squatting policy in the store.
2. **Update consent UX** — how new-capability prompts are batched on update.
3. **Data retention on uninstall** — default retain vs purge, and a grace window.
4. **WASM runtime** — when `runtime.kind: wasm` apps (sandboxed in-process) land vs native processes.

## 10. Logging from an app (D222)

pvosd starts every app with `PVFS_LOG_FORMAT=json` and its stdout/stderr
piped. Each line comes back through pvosd's own log, under `pvosd.service`,
as `pvosd/app[<id>] err: <the app's line>` — the same text it always was.

- **A Rust app on the SDK** calls `pvos_sdk::init_logging("<id>")` first
  thing in `main`, then logs with the SDK's macros:

  ```rust
  use pvos_sdk::{content, pv_info, pv_warn};
  pv_warn!("pvos.myapp.sync_failed", source = content(&url), error = content(&e);
           "myapp: sync from {url} failed: {e}");
  ```

  Each line is then a full record — severity, event name, category, classed
  fields — and pvosd keeps all of it when it relays the line (`service` =
  `app:<id>`). Event names are `pvos.<app>.<what>`; list new ones in
  [log-events.md](log-events.md) (a test fails on an unlisted one). Classify
  every value that is not plain metadata (`content` for paths, titles,
  errors; `identity` for names and emails; `actor` for keys; `net` for
  addresses), so a log destination at `minimal` privacy can take it out of
  the line too (D222 §Privacy).
- **An app in any other language** gets the same by printing schema-1 JSON
  records, one per line, on stderr (the fields are in PVFS
  `docs/32-log-events.md`); anything else it prints is relayed as
  `pvos.app.output` at `info`.
