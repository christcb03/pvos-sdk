# PVOS — Built-in Service Interfaces (07)

Status: **Draft for review**
Date: 2026-06-21
Depends on: [06 (service registry)](06-service-registry-and-behavior-plane.md), [00 §3.1/§7](00-pvos-architecture.md)

The default system services PVOS ships. Each is a **default, replaceable app** (doc 00 §3.1) implementing a **well-known service interface** — reached through the normal `CallService` path (doc 06), gated by a capability. Built-ins ship in the box; a third party can extend or (owner-gated) replace any of them by implementing the same interface.

Well-known names use the `pvos.` prefix: `pvos.keychain`, `pvos.scheduler`, `pvos.monitor`.

---

## As built (2026-10-04, D218)

The text below is the design as written (2026-06-21, with later "Shipped" notes); this section lists where the code differs. `lib.rs` is `crates/pvosd/src/lib.rs`.

- **The built-ins.** Five exist: `pvos.keychain`, `pvos.scheduler`, `pvos.monitor`, `pvos.notify` and `pvos.actors` (`crates/pvos-core/src/services.rs:84-170`). `pvos.sso` is not one of them.
- **§1 keychain.** `list` takes no argument. An entry grant has no "w": it names entries, and `put` over an existing entry and `delete` need custody — the entry must already be the caller's own (`lib.rs:7307-7316`, `:7383-7390`). D184 added three owner-only methods, `status`, `escrow` and `rewrap` — the companion's recovery copy of app secrets (`lib.rs:7224-7230`, `:7411-7549`).
- **§2 scheduler.** `schedule` is `one_shot{at_ms}` or `every{interval_ms, first_at_ms?}`, not cron (`crates/pvos-proto/src/behavior.rs:36-56`). An `actor` beside the job fields makes the job that member's, checked against their schedule capabilities (D31; `lib.rs:6636-6665`). Job-health reporting into `pvos.monitor` is not built.
- **§3 monitor.** The `apps()` field is `running`, not `attached` (`lib.rs:6888-6898`). The D18 role gate listed under "Still to come" is shipped (D31): with an `actor`, a member without see-machine gets only the apps shared with their role, and `platform`, `history` and `stop` are refused (`lib.rs:6815-6864`).
- **§3.5 `pvos.sso`.** Not built: no such service and no `sso` capability exist in `crates/`. What shipped is the opaque `actor` handle on `UiEvent` and `UiLifecycle` (D31, D39; `crates/pvos-proto/src/control.rs:366-388`) and **`pvos.actors`**, with one method: `holds(actor, cap) → {member, holds}` — whether the member behind an interaction holds a system capability (D38; `lib.rs:6745-6799`).
- **§3.6 notify.** `post`, `list`, `mark_read` and `dismiss` take an optional `member` (D56): that member's inbox; absent means the owner's (`lib.rs:7093-7108`). `email(member, subject, body?)` mails a member's registered address, at most 30 per app per hour (D55, D57; `lib.rs:7015-7083`). On the desktop each member sees their own inbox, not the owner's (D18; `lib.rs:941-975`).

**Since D218** (checked by D281, 2026-10-24; the line numbers above are D218's, so the functions are named here instead):
- **Six built-ins:** `pvos.dns` joined them (D262; `services.rs`, `dns_outcome` in `lib.rs`). One method, `resolve(name)`: the answer through the owner's app-DNS setting (Settings → Network, `pvos dns`), a split of home domains and bare names plus a default. A resolver that does not answer falls back to the host's; NXDOMAIN does not. It changes nothing for the server itself.
- **`pvos.actors.holds`** also takes `app_action` instead of `cap` (D259): whether the member holds one of the *calling* app's own `member_actions`, as the owner ticked them per member. An app never asks about another app's names (`actors_outcome`).
- **`pvos.notify`** gained `routing()` and `routing_applied(version)` (D264): the owner's notification routing from Settings → Notifications (Telegram chats, members' inboxes and email, D270), and the app's report that it applied that version (`notify_outcome`). The Monitoring app is the one caller.
- **Events** are per `(provider, topic)` since D254: an app emits only on its own topics, and hearing another provider needs a `Service` capability on it (doc 06).
- **`pvos.share`** phase 1 is built (§3.7, D280). Uploads with end-to-end encryption, request links, and production use are later.

---

## 1. `pvos.keychain` — secrets & identity storage

**Shipped M5 (2026-07-24); two-tier custody since M5b/D31.** Gated by the
**`secrets`** capability, scoped to named entries (`ServiceSel::Entries`).

```
get(entry)                   → {value_b64} | NotFound   // requires secrets:{entry}
put(entry, value_b64, app?)  → ok                        // requires secrets:{entry} w
list(scope)                  → [entry]                   // filtered to the caller's grants
delete(entry)                → ok
```

- **Values are opaque bytes**, and `get` returns **plaintext** to an
  authorized caller (M5 design §2b). An app that wants its
  secret hidden even from PVOS stores an app-encrypted blob as the value and
  decrypts client-side — same calls, same storage, its choice.
- **Custody has two tiers** ([M5b](milestones/M5b-app-key-secrets.md)):
  - *app tier* — sealed to the consuming app's derived, server-held key
    (master key at `<mount>/.pvfs/keychain.key`, 0600, never forest content).
    No companion on either path, so a secret can be stored from the browser
    and read by an unattended scheduled run. `put` picks this tier
    automatically for an app caller; an owner session names the app.
  - *owner tier* — sealed to the owner's companion encryption key; the
    companion is required to store **and** to read. This is the tier for
    personal secrets (and what pre-M5b entries are).
- **Custody is a second gate, independent of authority**: an app's `get`
  derives only its own key, so a valid `Entries` grant does not open a secret
  sealed to a different app. Owner sessions may open any app's entry.
- Every entry is one **P3 secure node** under the system `keychain` tree,
  which has no grants at all — PVFS default-deny means only the owner
  connection (pvosd) reaches it (the `key:`-only region of doc 02 §8).
- **Replaceable** by a "vault" app (owner-gated, §5) for different security
  properties (hardware token, different KDF, remote HSM) — D15, not built.

---

## 2. `pvos.scheduler` — timers & background jobs

Gated by the **`schedule`** capability. *(as built: see above — the schedule is `one_shot` or `every`, not cron)*

```
register(job{ schedule, action, payload }) → job_id   // schedule: cron-like or one-shot
cancel(job_id)                              → ok
list()                                      → [job]
```

- `action` is a **service call back into the registering app** (or an event) fired on schedule — so a job is "call my own service `X` at time `T`." Jobs persist as nodes (survive restart), and fire even if the app was stopped (it's started, or the call queues).
- The scheduler has its own job-health reporting into `pvos.monitor`.

---

## 3. `pvos.monitor` — what is running, what it costs, PVOS's health and logs, and stopping it

**Shipped (M8, 2026-07-27; `health` and `logs` D297, 2026-10-27)** — the
surface behind the System app (formerly Resources), `pvos status` and
`pvos logs`.

```
apps()                → per app: attached, supervised, pid, cpu %, rss, threads, surfaces
platform()            → the census live (attached/supervised/sessions/subscriptions/
                        calls in flight/consents pending) + host cpu %, memory, load, uptime
history()             → a rolling series of host samples for the graphs
health()              → {state, at_ms, checks: [{check, state ok|warn|bad, summary, detail}]},
                        worst first: pvosd, forests, apps, certificate, backup,
                        log shipping, disk, problems logged (D297)
logs(since?, until?, service?, level?, text?, event?, limit?, after?)
                      → {records: [{at_ms, level, service, event, component, message,
                        fields, cursor}], cursor, more}: pvosd's own journal (D297)
stop(app_id)          → terminate an app's backend
```

- **`health` and `logs` are machine-wide** (SeeMachine; a member with only
  SeeOwnApps is refused). `logs` reads pvosd's own unit's journal (found
  from `/proc/self/cgroup`), which holds pvosd's records and every app's and
  served pvfsd's, re-logged with `PV_SERVICE` = `pvosd`, `app:<id>` or
  `pvfsd`. It reads at most 20,000 entries a call, newest first, and filters
  the text and event itself; `after` (a cursor) follows, oldest first. A
  journal pvosd cannot read is the error `journal_unreadable` with the
  reason (not under systemd; the user is not in `systemd-journal`), never an
  empty list. `health`'s checks are pure functions in `crates/pvosd/src/health.rs`:
  a check that cannot look says `warn` and why, never `ok`.

- **`stop` is a separate method on purpose.** It means the existing capability
  vocabulary expresses both roles without a second service:
  `Methods(["apps","platform","history","health","logs"])` is a **read-only**
  monitor and cannot stop anything; an unrestricted `pvos.monitor` grant can. `m3_desktop` asserts
  that pair. (It reverses M8's first-slice decision to be read-only:
  this is "the main interaction for a user to interact with running processes and
  may be their only troubleshooting avenue for a while".) `stop` reuses the same
  path as the desktop's force-quit, so there is one way to end an app and one
  place it is logged; an app cannot stop itself.
- **History is sampled by `pvosd`**, not by whoever is watching: a series that
  only exists while a window is open is not history. The janitor keeps a fixed
  360-point ring (~30 min at 5s), bounded by construction. It is **in memory**, so
  a restart loses it; longer history wants coarser buckets in the forest, which is
  a different shape rather than more of the same.
- **Nothing is invented.** An app `pvosd` did not spawn has no pid, so cpu/rss
  come back `null` and `supervised` is false; CPU needs two samples, so the first
  reading reports `null` rather than 0% (which would read as idle).
- Host figures are the **machine's**, not the sum of PVOS apps — most of what runs
  on the box is not a PVOS app. CPU is busy-vs-idle across two readings of
  `/proc/stat`, with iowait counted as idle.

### Still to come

Per-app history series, storage per app region, `pvfsd`/`pvosd`'s own usage, and
the D18 role gate (an admin sees the machine; a member sees their own apps). The
publish/subscribe side below is the older design for app-supplied metrics and has
not been built yet:

```
publish(source, metrics|health)  → ok                 // any app plugs its health/metrics in
subscribe(alerts)                → stream of Alert     // (push) ServiceEvent
```

- **Extensible entry points:** any app publishes its own metrics/health into one place; PVOS publishes **system + app-process health** (liveness, restarts, resource use where it can see it). This is the "overall health monitoring and performance reporting" surface from doc 00 §7.
- Distinct from an app's *domain* monitoring (e.g. the IaC app watching Proxmox hosts is the app's concern; whether the IaC app is *running and healthy* is `pvos.monitor`'s).

---

## 3.5 `pvos.sso` — Simple Single Sign-On

*(as built: see above — `pvos.sso` is not built; apps use the `actor` handle and `pvos.actors`)*

The single-sign-on service, backed by the **companion** (doc 10). The user unlocks the companion **once**; `pvos.sso` then signs every fully-integrated app in. Gated by an **`sso`** capability (granted to integrated apps at install).

```
whoami()               → Principal       // the signed-in user (identity assertion)
session()              → { principal, since, tier }
sign_as_user(context)  → sig | Denied    // human-attributed signature, routed to the companion with context
```

- **Identity assertion** (`whoami` / `session`): an app learns the signed-in user without running its own login.
- **Signature brokering** (`sign_as_user`): the app passes a **human-readable context** ("App X wants to do Y"); `pvos.sso` forwards it to the companion, which displays it and returns the signature on approval. Apps write **no signing code**; there is **one** approval surface (doc 10 §4.1). The context protocol is the make-or-break detail (D19).
- Replacing the sign-on/identity service is among the **most sensitive** owner-gated acts (§5).

---

## 3.6 `pvos.notify` — notifications (M6, D33)

**Shipped 2026-07-26.** Apps emit; the OS keeps and delivers. See
[M6-notifications.md](milestones/M6-notifications.md).

```
post(level, title, body?, ref?, dedupe_key?) → id
list()                                       → the CALLER's own notifications
mark_read(id?) / dismiss(id?)                → count changed
```

- Persisted in the forest (`system/notifications/<id>`), so a 03:00 failure is
  still there in the morning — the case a toast cannot serve.
- `dedupe_key` collapses repeats into one record with a count, keeping the same
  id so the desktop's row stays stable, and resurfacing it as unread.
- **An app sees only its own; the desktop sees the owner's whole inbox.** The
  grant is deliberately cheap, so without that scoping it would double as a read
  channel onto every other app's business, and one app could clear another's
  alarm.
- Retention is count-based per app (200).

## 3.7 `pvos.share` — share links (D280, phase 1 built)

A link that lets someone without PVOS download files. The friend needs a
browser and nothing else. The owner makes the link from the desktop's
**Share** button, or with `pvos links`. Creating one, or changing its time
limit, is confirmed on the companion. Stopping one is not.

The token in the URL derives a secp256k1 link key (HKDF, domain
`pvos:share:v1`; a password is mixed in with Argon2id). That key holds an
expiring `r` grant on the named files, or on the folder. A folder link is
live: the friend sees the folder as it is when they open the page. The
share record stores the token so the log can show the URL again. It does
not store the password or the private key. `expires` of 0 means no time
limit.

`pvos-share` is a separate keyless process. On the test PVOS it listens on
the docker bridge and Traefik serves
`https://share.example.com/s/<token>` on port 443. An
unknown token, a stopped or expired link, and a wrong password all get the
same page. A file from the device the owner is signed in on is stored in
the forest first (an `Uploads` folder, unless they are adding to a folder
link). Those bytes are ordinary forest files. End-to-end encryption,
request links, and production use are later.
[D280](milestones/D280-share-links.md).

```
create({files | folder, kind: download, expires, password?}) → {id, url}
list() · revoke(id) · extend(id, until) · browse(path)
```

`POST /share-upload` stores a file from the signed-in desktop. It is not a
`CallService` method: a websocket frame cannot carry the bytes.

## 4. Why they're services, not a hidden API

Because built-ins are reached via `CallService`, there is **no second-class system API** — the keychain and a third-party vault app are invoked identically. This is what makes "writing a replacement for an OS service" the same activity as "writing an app" (doc 00 §3.1), and it keeps the platform's surface small.

---

## 5. Replacing a built-in (owner-gated)

1. A `tier: system` app declares it **provides** a well-known interface (e.g. `pvos.keychain@1`).
2. The **owner** approves the replacement (heavily gated — replacing the keychain means the new app sees every secret request; doc 00 §3.2/§4.4).
3. PVOS **re-routes** the well-known service name to the replacement provider; the default built-in steps aside (or is disabled).
4. Revoking the approval restores the default.

The interface is **versioned** (doc 06 §4), so a replacement must implement a compatible version, and consumers' negotiated-upgrade tests apply across the switch.

---

## 6. Open questions

1. ~~**Keychain ↔ `secure` module** — exact hand-off when PVFS P3 lands.~~
   **Resolved (M5, 2026-07-24):** the keychain *is* a thin front over P3
   secure nodes; §1 records the sealing tiers.
2. ~~**Scheduler durability/missed-fire policy** — catch-up vs skip when the host was down.~~
   **Resolved (M4c, DECISIONS D32, 2026-07-25):** skip. A job's fires sit on a
   grid anchored in absolute time, recomputed at load, so a restart does not
   push the next one later; occurrences missed while the daemon was down are
   skipped, not replayed — the right default for jobs that change
   infrastructure. A fire while the job is still running is recorded as
   `skipped`, never queued.
3. **Monitor retention** — how long metrics history is kept and where (ephemeral vs PVFS nodes; temp nodes fit, doc 00 §6).
4. **Partial replacement** — extending a built-in (adding methods) vs wholesale replacement.
