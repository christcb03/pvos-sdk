# PVOS — Service Registry & Behavior Plane (06)

Status: **Draft for review**
Date: 2026-06-21
Depends on: [04 §4.3](04-control-socket-protocol.md), [00 §6 (supersession)](00-pvos-architecture.md), [05](05-app-manifest-and-lifecycle.md)

The **behavior plane**: how apps offer abilities and call each other's (and PVOS's). The data plane is the shared graph (doc 00 §8); this is the live-action half, all over Channel 2.

---

## As built (2026-10-04, D218)

The text below is the design as written (2026-06-21); this section lists where the code differs. `lib.rs` is `crates/pvosd/src/lib.rs`, `services.rs` is `crates/pvos-core/src/services.rs`.

- **§1 provider.** The provider is the publishing **app id** (or `pvos` for a built-in), not a key (`services.rs:5-10`, `:25-30`); a call is routed to the connection attached under that app id (`lib.rs:6134-6150`). Key-based provider identity waits for the app-store work.
- **§2 publish.** A `/services` record is written by pvosd as the owner, not signed by the provider: the provider is authenticated by its Channel-2 session, and the record names it (`services.rs:5-10`, `:172-212`).
- **§2 call.** An app may always call its own services, and the owner's admin session needs no grant (`lib.rs:6083-6098`). `CallService` also carries `provider` (doc 04, As built).
- **§2 events.** Provider-scoped since PVOS D254 (2026-10-19): subscriptions are per `(provider, topic)`, an app emits only on its own topics, an event names its provider, and hearing another provider needs a `Service` capability on it, checked at subscribe and again at each delivery. Before D254 any app could subscribe and emit on any topic (D218 §2.3).
- **§4 negotiated upgrade.** Design only. `CallService`'s `version` is ignored (`lib.rs:6080`), a provider has one live version, and discovery returns that one (`services.rs:244`). No interface node, pin or compatibility test exists.
- **§6 failures.** The codes a caller sees are `denied` (no capability), `not_found` (not published), `unavailable` (the provider is not connected) and `timeout` — no reply within 30 s (`lib.rs:46`, `:6102-6162`, `:1124-1161`). Since D260 (2026-10-20) a provider whose connection closes with calls unanswered fails them `unavailable` at the close, instead of leaving them to the 30 s sweep.
- **§6.1 async jobs.** The provider answers with an ordinary `Ok` whose value is `{"job_id": "<id>"}`; there is no `Job` reply. The topic is `job/<id>`, not `job:<id>`; the caller subscribes itself; the last event carries `done`. There is no `CancelJob` (`crates/pvos-proto/src/behavior.rs:28-31`; `crates/pvosd/tests/m2_services.rs:486-506`).
- **API methods (D290).** `ServiceDecl.api` names the methods the CLI and REST may call. A method only in `methods` — a scheduler callback, a scan — stays callable by a grant and is not an operation. `pvos apps` lists the declared ones. `pvos call` and `POST /api/<service>.<method>` call one.

---

## 1. A service is `(provider, name)`

Like tags (PVFS doc 10), a service is scoped to its **provider's key** — `greeter` from app A is not `greeter` from app B. A service has a **version** (semver), an **interface** (a content-addressed schema node listing methods + arg/result shapes + event topics), and a **provider** (the app, or PVOS for built-ins).

```jsonc
ServiceDecl {
  "name": "greeter",
  "provider": "key:<A>",            // implicit = the publishing connection's principal
  "version": "1.3.0",
  "interface": "pvfs://…schema",    // methods, arg/result schemas, event topics
  "methods": ["greet", "farewell"]
}
```

---

## 2. Register, discover, call (Channel 2)

- **Publish:** `PublishService{decl}` — recorded in `/services` (signed by the provider) and in `pvosd`'s live table. Any app may publish; no special permission to *offer*.
- **Discover:** `DiscoverServices{query}` → `[ServiceInfo{name, provider, versions, interface_ref}]`. Returns PVOS built-ins and other apps' services; surfaces all available **versions** (for §4).
- **Call:** `CallService{service, method, args, version?}`. `pvosd` **authorizes** (caller holds the `Service` capability for that `(provider, name)`), then **routes** to the provider via `IncomingServiceCall`; the provider replies `ServiceReply`. Correlated by `call_id` (doc 04 §5).
- **Events:** `Subscribe{topic, provider}` / provider `emit` → **(push)** `ServiceEvent{topic, payload, provider}`. Topics are provider-scoped, and hearing another provider needs a `Service` capability on it (D254).

---

## 3. Permission model

- **Offering** a service needs nothing special — apps publish freely.
- **Calling** a service requires a **`Service` capability** scoped to `(provider, name, sel)` (doc 00 §4.2 — the single canonical non-storage capability; `secrets`/`schedule`/`health` are well-known aliases over it). Granted like any capability: declared in the consumer's manifest (`services_consumed`), consented at install, owner-gated if sensitive (doc 05 §3). Built-in and third-party services use the **same** check on every `CallService`.
- **Providers may additionally gate** per-caller (their own logic), but the capability is the platform-level gate.
- Discovery can be open (list names) while calling stays gated — so apps can *see* what exists without being able to *use* it.

This means a malicious app can't silently invoke another's abilities: it needs a granted, revocable capability, and every call is checked live against the effective set (doc 02 §4).

---

## 4. Binding & negotiated upgrade (the self-healing part)

A consumer's `services_consumed` entry names `(provider, name)` + a version constraint. Binding uses the **supersession / dual-resolution** model (doc 00 §6) *(as built: see above — design only)*:

- The provider's service interface is a **versioned node**; each new version supersedes the prior.
- A consumer **pins** the specific interface version it was built against.
- When the provider ships a new version (supersession), the consumer's runtime runs **its own compatibility tests** against the new interface (doc 00 §6.3):
  - **pass** → re-pin to the new version (silent, clean upgrade);
  - **fail** → keep the pinned version and **notify the maintainer** with the error.
- A simpler, discouraged mode: pin-strict + notify-only (manual).

So services compose with the same safe-upgrade guarantees as everything else — "one update ripples, nothing silently breaks."

---

## 5. Built-in services are providers

Keychain, scheduler, and health/monitoring (doc 07) are reached through the *same* `CallService` path, with **PVOS as the provider authority**. There is no separate "system API" — §4.2 capabilities and §4.3 services are one mechanism (doc 04 §4.3). Replacing a built-in (doc 07 §5) just changes which provider serves a well-known service name.

---

## 6. Failure & delivery semantics (v1)

- **Calls** are request/response with a timeout; a provider crash mid-call returns a typed `Error` to the caller (no hang).
- **Events** are best-effort, at-most-once; no durable queue in v1 (durable/replayable event log is a later option, and could ride PVFS).
- **Provider down:** `CallService` to an unpublished/stopped provider returns `Unavailable`; consumers handle gracefully (degrade per `optional` in the manifest).

### 6.1 Long-running calls — async jobs (D17)

Some services take minutes (provision a VM, transcode, deploy), so a single blocking response is wrong. `CallService` supports an **async job** shape, opt-in per method (declared in the interface) *(as built: see above — the reply shape and topic name differ, and there is no cancel)*:

- The provider may answer with a **`Job { job_id }`** instead of a final result.
- **Progress** streams as `ServiceEvent { topic: "job:<id>", … }` (the caller is auto-subscribed).
- **Completion** is a final `ServiceEvent { job:<id>, done, result | error }`.
- The caller may `CancelJob { job_id }` (provider-honored).

Short calls stay plain request/response. This is how MediaForest waits on `iac.provision` (examples/mediaforest-app.md MF3).

---

## 7. Open questions

1. **Streaming results** (vs single response) and **backpressure** (doc 04 §10.1).
2. **Durable / replayable events** — keep ephemeral, or persist topics as PVFS nodes for replay.
3. **Interface schema language** — JSON Schema vs a typed IDL for `interface`.
4. **Cross-residency calls** — an isolated app (own forest, doc 00 §3.5) calling/serving across the bridge; routing + auth over the cross-forest grant.
