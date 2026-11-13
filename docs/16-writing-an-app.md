# PVOS — writing an app (16)

Status: **guide, current as of PVOS main 2026-10-14** (D249). The worked
example is the greeter, `crates/pvos-app-greeter/src/main.rs`: about 240
lines, and every piece below appears in it. To start from a running app, see
[getting started](getting-started.md). The reference docs behind this
guide:
- [05](05-app-manifest-and-lifecycle.md): the manifest and lifecycle;
- [04](04-control-socket-protocol.md): the control socket;
- [06](06-service-registry-and-behavior-plane.md): services and events;
- [07](07-built-in-services.md): the built-in services;
- [08](08-web-desktop-and-view-model.md): the view model.

Each has an "As built" section where the code differs from the design.

## 1. What an app is

An app is a **process pvosd starts and supervises**, with a **folder**
holding its manifest, its binary and (for a UI) its `ui/`. It has:
- **its own key**, minted at install and kept in its app directory as
  `device.key`. pvosd knows the app by it;
- **its own region** in the system forest (`/apps/<id>/data`), read and
  written through pvfsd with that key;
- **only the capabilities the owner granted**: storage elsewhere, or a
  service (default-deny: nothing is ambient).

It talks to PVOS over the **control socket**: services, events, UI and
capability requests. Its bytes go to pvfsd directly; PVOS brokers who may
touch what.

## 2. The manifest

`manifest.json` in the app's folder; the type is `AppManifest` in
`crates/pvos-proto/src/manifest.rs`.

```json
{
  "id": "com.example.notes",
  "version": "0.1.0",
  "api_version": 1,
  "display_name": "Notes",
  "description": "What it does, in a sentence the owner reads at install.",
  "icon": "icon.svg",
  "tier": "user",
  "residency": "integrated",
  "capabilities": {
    "required": [
      { "kind": "storage", "scope_hint": "own-region", "reason": "your notes" },
      { "kind": "service", "scope_hint": "pvos.notify", "reason": "reminders" }
    ],
    "optional": []
  },
  "services_provided": [{ "name": "notes", "version": "0.1.0", "methods": ["list"] }],
  "ui": { "surfaces": [{ "name": "main", "mode": "viewmodel" }] },
  "headless": false,
  "admin_only": false,
  "runtime": { "kind": "native", "entrypoint": "./notes" }
}
```

- **`id`**: reverse-DNS. `pvos`, `pvos.*`, anything starting `@`, and ids
  with `/`, `.` or `..` parts are refused (D237). Installing an id another
  app holds is a take-over, and the CLI asks first (D204).
- **`capabilities`**: what the owner is asked to grant at the first start.
  `reason` is shown with the request. An app can also ask later, just in
  time (`request_capability`): a consent prompt reaches the owner, and it
  expires after 10 minutes.
- **`ui.surfaces`**:
  - `viewmodel` (Mode B): the app pushes a server-driven view, the
    preferred kind;
  - `iframe` (Mode A): a sandboxed `ui/index.html`, one self-contained file
    (doc 08 "As built").
- **`admin_only`**: the app may never be shared below admin.
- **`member_actions`** (D259): things a member may be allowed to do in
  this app, `[{ "name": "acknowledge", "description": "Acknowledge an
  alert" }]`. A name is 1–32 characters of `a-z 0-9 _ - .`, starting with a
  letter; at most 32; a description of 1–120 characters. The install refuses
  a bad list. See §5 for asking about them.
- **`requires`**: `{ "pvfs_proto": N, "pvos_api": N }`, the protocol floors
  pvosd checks at launch.
- **`icon`**: a file in `ui/`.
- **Parsed and not used yet:** `tier` and `residency` gate nothing today
  (BACKLOG).

## 3. Attaching

pvosd starts the app with two variables set:
- `PVOS_CONTROL_SOCKET`: where to attach;
- `PVOS_APP_DIR`: where its `device.key` is.

```rust
pvos_sdk::init_logging("notes");                         // §7
let control = std::env::var("PVOS_CONTROL_SOCKET")?;
let key = DeviceKeyCache::load(Path::new(&std::env::var("PVOS_APP_DIR")?))?;
let conn = pvos_sdk::connect(Path::new(&control), &key.pubkey(), |d| {
    crypto::sign_digest(&key.signing_key, d).unwrap()
})?;
let ctx = conn.context();          // app_id, region_root, capabilities, api_version
```

The attach is a signed challenge: answer within 30 s (D237).
`conn.wait_closed()` blocks until pvosd ends the session. Exit then: the
app is restarted on demand, and an idle app may be asked to park (D45,
`on_park`).

## 4. Storage

`conn.pvfs(&pubkey, sign)` opens a PVFS client to pvfsd under the app's
key. Read and write in `ctx.region_root` (mkdir, add files, payloads,
secure blobs). Anywhere else needs a storage grant. A grant can be passed
on to another app with `conn.delegate(...)`, narrower and shallower than
what the app holds; the platform enforces both (D237: the fold enforces the
depth). `on_capability_changed` tells the app when a grant arrives or is
revoked.

## 5. Services and events

- **Provide:** set the handler first, then publish, so no call finds the
  app without one.

  ```rust
  conn.on_call(|_service, method, args| match method {
      "list" => CallOutcome::Ok { value: json!([]) },
      other => CallOutcome::Err { code: "no_such_method".into(), message: other.into() },
  });
  conn.publish(ServiceDecl { name: "notes".into(), version: "0.1.0".into(),
                             interface: None, methods: vec!["list".into()],
                             api: vec![ApiMethod { name: "list".into(), companion: false }] })?;
  ```

- **Call:** `conn.call(&provider, "service", "method", args)` needs a
  service grant for it. `conn.discover(...)` lists what is published. A
  long call returns a job id at once and reports progress as events on
  `job/<id>` (the greeter's `greet_slowly`; doc 06 §6.1).
- **Events:** a topic belongs to its provider (PVOS D254).
  `conn.emit(topic, payload)` publishes on your own topics, and
  `conn.subscribe(topic, ...)` listens to them. `conn.subscribe_to(provider,
  topic, ...)` listens to another provider's, such as an async job's
  `job/<id>`. That needs a `Service` capability on that provider, and is
  refused `denied` without one. Each event is checked again when it is
  delivered, so a revoked grant stops the next one. An event says which
  provider sent it, and no app can emit as another.
- **Built-in services** (doc 07), each through a grant:
  - `pvos.keychain` (§6);
  - `pvos.scheduler`: jobs that call a service on a schedule, waking the
    app if it is parked;
  - `pvos.notify`: the owner's notifications and members' email. Since
    D264, also `routing` (the notification routing set in Settings →
    Notifications: destinations, and who gets pages, summaries and the
    digest) and `routing_applied {version}`, for the app that delivers it.
    Since D270 that app also posts each recorded notice to the inbox and
    email destinations (`post`, `list`, `email`).
    Subscribe to `notify.routing` (provider `pvos`) to hear each save;
  - `pvos.monitor`: what is running;
  - `pvos.actors`: what the person behind a UI event may do.
  - `pvos.dns` (D262): `resolve {name}` → `{name, addresses, via,
    fell_back, nxdomain, note}`, by the owner's DNS setting for apps
    (Settings → Network). For HTTP, hand `ureq` the SDK's resolver:
    `AgentBuilder::new().resolver(move |n: &str| conn.socket_addrs(n))`.
    Without the grant, `socket_addrs` uses the host's resolver, as before.
    Pin certificates as Monitoring does: a name's address is not the
    trust.
  - `pvos.store` (D336): what you keep for one person — their settings,
    their history — in THEIR forest, sealed to them: the box's owner
    cannot read it. `conn.person_store_get(actor)` → `Option<Vec<u8>>`,
    `conn.person_store_put(actor, bytes)`; one blob per app and person,
    replaced whole. It answers `locked` until the person has unlocked
    their data in this session; say so in your UI and keep nothing for
    them elsewhere. Data that is shared (a library, a share link) does
    not go here. Background work (D336 part 3): a person may allow your
    app to work on what it keeps for them while they are away (their
    Settings → Background work); `conn.person_store_jobs()` gives one
    job actor per person who did, for `person_store_get`/`put` from a
    scheduled job. Ask nobody to allow it unless a job needs it.

- **Who may do what** (D259). A UI event carries an opaque `actor`. Ask
  `pvos.actors` `holds` with `{"actor", "cap"}` for a system capability
  (`manage_apps` = the owner and admins) or `{"actor", "app_action"}` for
  one of your own `member_actions`. Not both in one call. The answer is
  `{"member", "holds"}`. An app action is answered only for your app's own
  declared names: the owner holds them all, a member holds the ones the
  owner ticked, and a name you do not declare (renamed, removed, or
  another app's) is `false`. The usual rule is to accept either: the
  system capability for the owner and admins, or your own action for a
  member (the Monitoring app's `who`).

## 6. Secrets

`pvos.keychain`, with a grant naming the app's entries
(`pvos grant --service pvos.keychain --entries a,b`, or the manifest's
request). An entry the app writes is sealed to the app's key and escrowed
to the owner's companion, so a rebuilt box can re-wrap it (D184).

```rust
conn.call(&ProviderId::pvos(), "pvos.keychain", "put",
          json!({ "entry": "notes-api-key", "value_b64": B64.encode(value) }))?;
let v = conn.call(&ProviderId::pvos(), "pvos.keychain", "get", json!({ "entry": "notes-api-key" }))?;
```

The owner can also put one for the app: `pvos secret put notes-api-key --app com.example.notes`.

## 7. Logs

`pvos_sdk::init_logging(app_id)`, then the SDK's `pv_info!`, `pv_warn!`
and the rest (the same records as PVFS's, doc 32). pvosd relays the app's
output into its own journal as records tagged with the app. Expected,
self-healing behaviour logs at debug. A fault that persists warns. An error
means data is at risk. A test can hold every event name your app logs to a list you keep, with
`pvfs_log::registry::check_repo`.

## 8. A view-model UI (Mode B)

Build a `ViewModel` from `pvos_proto` components (doc 08 §4: tables, forms,
text areas, cards, charts, a streaming `log`, …). Then:
- `conn.push_view_model("main", vm)` renders it for every session with the
  surface open;
- `push_view_model_for(..., actor)` renders it for one session (D39);
- `on_ui_event` delivers a form's or a button's action with an opaque actor
  handle;
- `on_lifecycle` reports a window opening, focusing and closing; push the
  view on `Open`;
- `append_log(surface, component, lines)` streams into a `log` component
  without a re-push.

A view model over 4 MiB is refused (D209). pvosd relays view models
opaquely, so a new component needs only a desktop that draws it (D47).

## 9. Building and installing it

`pvos-dev package` (the dev kit) builds the folder. On a server running PVOS:

```bash
pvos install ./notes          # shows what it asks for, asks for approval
pvos start com.example.notes  # or open it from the desktop's launcher
pvos list                     # its grants, effective or not
pvos share com.example.notes member   # if members should use it
```

`pvos install` records where the folder is: the manifest's entrypoint
becomes an absolute path into it, so the folder must stay. It imports `ui/`
into the forest, pinned by hash (`integrity.ui_root`, M3.7), so pvosd never
serves UI bytes from the host's disk. Re-run it to update. `pvos apps check` says whether the
manifest pvosd enforces still matches the folder's.

## 10. Testing

The dev kit is the real `pvosd` and `pvfsd`, and `pvos-devkit` drives them from a
test (D306): see [getting started](getting-started.md). `pvos-dev new` writes an
end-to-end test to start from. With no kit, a test fails and says how to get one.
