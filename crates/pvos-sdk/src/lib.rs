//! `pvos-sdk` — the toolkit an app links to talk to PVOS.
//!
//! Depends on `pvos-proto` and the public PVFS crates (`pvfs-client-core` for
//! storage, `pvfs-crypto` for the app's key), NOT `pvos-core` or the PVFS engine
//! — apps build against a small, kernel-free surface, and this crate builds with
//! no PVOS or PVFS source beside it (D306). See docs 04, 05, 06.
//!
//! M2 session model: one long-lived, multiplexed connection. A reader thread
//! routes correlated responses to blocked requesters and dispatches push
//! frames: UI events + lifecycle through ONE ordered worker (a user's clicks
//! arrive in the order they were made); incoming service calls, events, and
//! capability changes each on a fresh thread. Requests are plain blocking
//! calls with a timeout. Outbound view-model pushes are ASYNC (D43): queued
//! on a coalescing outbox (latest frame per surface+actor wins) drained by
//! one sender thread — `push_view_model_for` returning Ok means QUEUED, not
//! delivered; the next render heals a dropped frame. A connection that
//! answers nothing (six consecutive dead-air requests) makes the process
//! exit(70), loudly, so supervision respawns it with a fresh connection.
//!
//! Provider surface: `on_call` + `publish`. Consumer surface: `discover`,
//! `call`, `subscribe`/`unsubscribe`, `emit`. Delegation: `delegate` runs the
//! doc 04 §4.2 helper flow — pre-flight validation over Channel 2, the
//! **app-signed** record appended via Channel 1, then a refold notify.

use std::collections::HashMap;
use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use pvos_proto::frame::{read_frame, write_frame};
use pvos_proto::{
    auth_digest, CallOutcome, CapChange, Capability, ClientMsg, Context, Depth, Grant, GrantId,
    GrantRecord, Issuer, ProviderId, ServerMsg, ServiceInfo, Subject,
};
use serde_json::Value;

// PVOS D222 — logging. An app logs through the SDK with no `pvfs-log`
// dependency of its own: `use pvos_sdk::{pv_warn, content};` then
// `pv_warn!("pvos.<app>.<what>", path = content(&p); "<app>: …{p}…")`. The
// macros expand through `$crate`, so the re-export is all an app needs. A
// field's class (`content`, `actor`, `net`, `identity`, `meta`; a bare
// string or number is `meta`) tells a destination what personal data it may
// keep (D222 decision 3a); every value the sentence prints that is not
// `meta` must also be a classed field, or it cannot be taken out of it.
pub use pvfs_log::{
    actor, content, identity, meta, net, pv_debug, pv_error, pv_info, pv_notice, pv_warn,
};

/// The manifest, the control socket, the view model (D306): one dependency for
/// an app.
pub use pvos_proto as proto;

/// PVFS, as an app uses it (D306): `Client` is what [`Connection::pvfs`] returns.
pub mod pvfs {
    pub use pvfs_client_core::*;
    /// PVFS's wire types, for what `Client` does not re-export.
    pub use pvfs_proto as wire;
}

/// The app's key, signatures, encryption and access rules (D306).
///
/// ```no_run
/// use pvos_sdk::keys::{crypto, identity::DeviceKeyCache};
/// let key = DeviceKeyCache::load(std::path::Path::new("/app/dir")).unwrap();
/// let sig = crypto::sign_digest(&key.signing_key, &[0u8; 32]).unwrap();
/// # let _ = sig;
/// ```
pub mod keys {
    pub use pvfs_crypto::{acl, crypto, encoding, envelope, identity, IntegrityReason, PvfsError};
}

/// PVOS D222: set up this app's logger. Call it as the first statement of
/// `main`, with the app's id.
///
/// pvosd starts every app with `PVFS_LOG_FORMAT=json`, so once this has run
/// each `pv_*!` line reaches pvosd as a schema-1 JSON record on stderr, and
/// pvosd relays it with its level, event name and fields kept (`service`
/// becomes `app:<id>`; the journal line reads as before). Outside pvosd (a
/// terminal, a test) the same lines print as plain text, exactly as written.
/// A line printed before this call, or by an app that never calls it, is
/// relayed as plain output at `info` (`pvos.app.output`).
///
/// An app in another language gets the same treatment by printing schema-1
/// JSON lines on stderr — see PVOS `docs/milestones/D222-structured-logging.md`,
/// decision 12 (the record's fields are in decision 1).
pub fn init_logging(app_id: &str) {
    // false = a logger was already set (a line was logged first, or a second
    // call): the first configuration stands, which is what we want.
    let _ = pvfs_log::init_daemon(app_id);
}

/// How long a blocking request waits for its correlated response. Routed
/// calls get longer than the daemon's own 30s provider TTL so the daemon's
/// timeout error arrives before the SDK gives up.
const REQUEST_TTL: Duration = Duration::from_secs(35);

/// Node type of grant-log records (mirrors `pvos-core`; the SDK avoids the
/// kernel crate by design).
const TYPE_GRANT_RECORD: &str = "pvos.grant-record";

#[derive(Debug)]
pub enum SdkError {
    Io(io::Error),
    Protocol(String),
    /// A typed error frame from `pvosd`.
    Server { code: String, message: String },
    /// The connection closed or the request timed out.
    Disconnected,
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::Io(e) => write!(f, "io: {e}"),
            SdkError::Protocol(m) => write!(f, "protocol: {m}"),
            SdkError::Server { code, message } => write!(f, "{code}: {message}"),
            SdkError::Disconnected => f.write_str("disconnected"),
        }
    }
}
impl std::error::Error for SdkError {}
impl From<io::Error> for SdkError {
    fn from(e: io::Error) -> Self {
        SdkError::Io(e)
    }
}

type Result<T> = std::result::Result<T, SdkError>;

/// Handler for incoming service calls (provider side). Runs on its own
/// thread; the returned outcome is sent back as the `ServiceReply`.
pub type CallHandler = Arc<dyn Fn(&str, &str, Value) -> CallOutcome + Send + Sync>;
/// Handler for a subscribed topic's events.
pub type EventHandler = Arc<dyn Fn(Value) + Send + Sync>;
/// Handler for capability-change pushes.
pub type CapHandler = Arc<dyn Fn(CapChange, Capability) + Send + Sync>;
/// Handler for UI events on a rendered surface (surface, action, payload,
/// actor). `actor` (D31) is the opaque handle for the member behind the
/// interaction — echo it in service-call args (`"actor": …`) to act on
/// their behalf; ignore it to act as the app.
pub type UiEventHandler = Arc<dyn Fn(&str, &str, Value, Option<&str>) + Send + Sync>;
/// D45: may the app park (exit for supervised respawn) right now?
/// Return false while work is in flight; flush anything dirty before
/// returning true — exit(0) follows immediately.
pub type ParkHandler = Arc<dyn Fn() -> bool + Send + Sync>;
/// Handler for a surface's window lifecycle (surface, phase, actor).
/// `actor` (D39) is the session behind the window — the same opaque handle
/// UI events carry — so a per-viewer app can render for the opener.
pub type LifecycleHandler = Arc<dyn Fn(&str, pvos_proto::UiPhase, Option<&str>) + Send + Sync>;

/// One queued UI delivery. UI events and window lifecycle share a single
/// queue because their *relative* order is meaningful too: a surface's `Open`
/// must land before the first click on it.
enum UiJob {
    Event {
        surface: String,
        action: String,
        payload: Value,
        actor: Option<String>,
    },
    Lifecycle {
        surface: String,
        phase: pvos_proto::UiPhase,
        actor: Option<String>,
    },
}

struct Inner {
    writer: Mutex<UnixStream>,
    pending: Mutex<HashMap<u64, mpsc::Sender<ServerMsg>>>,
    /// PVOS D254: handlers by `(provider, topic)`; `None` is this app's own
    /// topics.
    events: Mutex<HashMap<(Option<String>, String), EventHandler>>,
    on_call: Mutex<Option<CallHandler>>,
    on_cap: Mutex<Option<CapHandler>>,
    on_ui_event: Mutex<Option<UiEventHandler>>,
    on_lifecycle: Mutex<Option<LifecycleHandler>>,
    on_park: Mutex<Option<ParkHandler>>,
    /// Lifecycle pushes that arrived BEFORE the app registered its handler
    /// (the desktop can open a window while the app is still booting);
    /// drained by `on_lifecycle` so no Open is ever lost.
    pending_lifecycle: Mutex<Vec<(String, pvos_proto::UiPhase, Option<String>)>>,
    /// Ordered hand-off to the single UI worker (see `ui_worker`).
    ui_tx: Mutex<Option<mpsc::Sender<UiJob>>>,
    /// View-model pushes ride an outbox drained by ONE sender thread
    /// (D43): only the LATEST view per (surface, actor) is kept — a
    /// stale frame is worthless the moment a newer render exists — and
    /// the enqueue never touches the socket, so a peer that stops
    /// reading can no longer block an app thread mid-push (the frozen
    /// "starting…" incident: a 517 KB push wedged in send() while the
    /// app's state lock was held).
    outbox: (Mutex<Outbox>, Condvar),
    /// Set when the session ends; `wait_closed` parks on it.
    closed: (Mutex<bool>, Condvar),
    next_req: AtomicU64,
    /// Consecutive request failures (send error or reply timeout), reset
    /// by any success. A control connection that answers nothing is not a
    /// transient — pvosd may be holding a half-dead socket for us (the
    /// D43 morning incident: its reader gone, writer alive, every request
    /// timing out forever). An app in that state is both useless and
    /// invisible, so after [`MAX_CONN_FAILURES`] in a row the process
    /// exits loudly and supervision respawns it with a fresh connection
    /// on the next open.
    conn_failures: AtomicU64,
    /// D59: incoming service calls whose handler hasn't replied yet.
    /// Counted on the READER thread — before the handler thread spawns —
    /// so a ParkHint queued behind a fire always sees it in flight. A
    /// non-zero count vetoes parking: the scheduler may have started this
    /// very process FOR that call, and exit(0) would strand the work.
    calls_inflight: AtomicU64,
}

/// Consecutive `request_within` failures before the process gives up on
/// its control connection (see `Inner::conn_failures`).
const MAX_CONN_FAILURES: u64 = 6;

#[derive(Default)]
struct Outbox {
    /// Latest view model per (surface, actor) — replaced, never queued.
    latest: HashMap<(String, Option<String>), pvos_proto::ViewModel>,
    /// FIFO of keys with a pending frame (no duplicates).
    order: std::collections::VecDeque<(String, Option<String>)>,
}

impl Inner {
    fn send(&self, msg: &ClientMsg) -> Result<()> {
        write_frame(&mut *self.writer.lock().unwrap(), msg)?;
        Ok(())
    }

    fn request_within<B>(&self, ttl: Duration, build: B) -> Result<ServerMsg>
    where
        B: FnOnce(u64) -> ClientMsg,
    {
        let req_id = self.next_req.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(req_id, tx);
        if let Err(e) = self.send(&build(req_id)) {
            self.pending.lock().unwrap().remove(&req_id);
            self.note_conn_failure();
            return Err(e);
        }
        match rx.recv_timeout(ttl) {
            // A server-side error is still a WORKING connection.
            Ok(ServerMsg::Error { code, message, .. }) => {
                self.conn_failures.store(0, Ordering::Relaxed);
                Err(SdkError::Server { code, message })
            }
            Ok(msg) => {
                self.conn_failures.store(0, Ordering::Relaxed);
                Ok(msg)
            }
            Err(_) => {
                self.pending.lock().unwrap().remove(&req_id);
                self.note_conn_failure();
                Err(SdkError::Disconnected)
            }
        }
    }

    /// See `conn_failures`: enough consecutive dead-air requests and the
    /// only honest move left is a loud exit + supervised respawn.
    fn note_conn_failure(&self) {
        let n = self.conn_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= MAX_CONN_FAILURES {
            pv_error!(
                "pvos.sdk.connection_dead", failures = n;
                "pvos-sdk: {n} consecutive control-connection failures — the connection is \
                 dead; exiting so supervision can respawn with a fresh one"
            );
            std::process::exit(70);
        }
    }

    /// The blocking push — outbox-sender-thread ONLY (D43). Everything
    /// else enqueues via [`AppConn::push_view`].
    fn push_view_now(
        &self,
        surface: String,
        view_model: pvos_proto::ViewModel,
        actor: Option<String>,
    ) -> Result<()> {
        let view_model =
            serde_json::to_value(&view_model).map_err(|e| SdkError::Protocol(e.to_string()))?;
        match self.request_within(REQUEST_TTL, |req_id| ClientMsg::PushViewModel {
            req_id,
            surface,
            view_model,
            actor,
        })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// Hand a UI delivery to the ordered worker.
    fn queue_ui(&self, job: UiJob) {
        if let Some(tx) = self.ui_tx.lock().unwrap().as_ref() {
            let _ = tx.send(job);
        }
    }
}

/// Drain the view-model outbox: latest frame per (surface, actor),
/// oldest key first (D43). A failed or timed-out push is logged and the
/// frame dropped — the next render re-enqueues, so correctness never
/// rests on any single push landing; a peer that stops reading stalls
/// only THIS thread, never the app.
fn push_sender(inner: Arc<Inner>) {
    loop {
        let job = {
            let (lock, cv) = &inner.outbox;
            let mut ob = lock.lock().unwrap();
            loop {
                if let Some(key) = ob.order.pop_front() {
                    let vm = ob.latest.remove(&key);
                    break vm.map(|vm| (key, vm));
                }
                if *inner.closed.0.lock().unwrap() {
                    return;
                }
                let (guard, _) = cv
                    .wait_timeout(ob, Duration::from_millis(500))
                    .expect("outbox lock poisoned");
                ob = guard;
            }
        };
        let Some(((surface, actor), vm)) = job else { continue };
        if let Err(e) = inner.push_view_now(surface.clone(), vm, actor) {
            // Delivery failures also feed the dead-connection detector in
            // `request_within` — the sender itself just drops the frame.
            pv_warn!("pvos.sdk.view_push_failed", surface = &surface, error = content(&e);
                "pvos-sdk: view push for '{surface}' failed: {e}");
        }
    }
}

/// Deliver UI events and lifecycle pushes to the app **one at a time, in
/// arrival order**.
///
/// The desktop sends a user's interactions sequentially down one socket, so
/// the app has to see them in that order: a "sub-folders: on" toggle followed
/// by "import" must not import without the toggle. Dispatching each event on
/// its own thread (as this did originally) raced — and the race was real, not
/// theoretical: a fast double-interaction reordered them, which is exactly
/// how a user clicks.
///
/// The trade: a handler that blocks holds up the queue behind it, so handlers
/// must stay short and hand long work to their own thread (as the IaC app's
/// run executor does).
fn ui_worker(rx: mpsc::Receiver<UiJob>, inner: Arc<Inner>) {
    for job in rx {
        // A panicking handler must not take the worker with it. Without this,
        // one bad click makes the app permanently deaf — every later event and
        // lifecycle push queues behind a dead thread, which looks exactly like
        // a window hanging on "starting…" (the shape of a real incident here,
        // reached by a deadlock rather than a panic).
        //
        // Honest limit: if the handler panicked while holding one of the app's
        // own locks, that lock is now poisoned, so an app that does
        // `state.lock().unwrap()` will keep panicking on every later event. The
        // worker surviving turns "silently deaf forever" into "a loud line per
        // event", which is the difference between an unfindable hang and a
        // diagnosable fault.
        // Name the job before running it — a slow handler is invisible
        // otherwise, and every job behind it on this ORDERED worker waits
        // (the D44 slow-window-open investigation).
        let what = match &job {
            UiJob::Event { surface, action, .. } => format!("event {surface}/{action}"),
            UiJob::Lifecycle { surface, phase, .. } => format!("lifecycle {surface}/{phase:?}"),
        };
        let t0 = std::time::Instant::now();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch_ui(&inner, job)
        }));
        if t0.elapsed().as_millis() > 1500 {
            pv_warn!(
                "pvos.sdk.ui_job_slow", job = content(&what),
                duration_ms = t0.elapsed().as_millis() as u64;
                "pvos-sdk: SLOW ui job ({what}) took {}ms — later events waited behind it",
                t0.elapsed().as_millis()
            );
        }
        if let Err(e) = outcome {
            let what = e
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            pv_error!("pvos.sdk.ui_handler_panicked", error = content(&what);
                "pvos-sdk: UI handler panicked ({what}) — worker survived; if the app's own lock was poisoned, later events will fail loudly too");
        }
    }
}

/// Deliver one queued UI job to the app's handler.
fn dispatch_ui(inner: &Arc<Inner>, job: UiJob) {
    {
        match job {
            UiJob::Event {
                surface,
                action,
                payload,
                actor,
            } => {
                let handler = inner.on_ui_event.lock().unwrap().clone();
                if let Some(h) = handler {
                    h(&surface, &action, payload, actor.as_deref());
                }
            }
            UiJob::Lifecycle { surface, phase, actor } => {
                let handler = inner.on_lifecycle.lock().unwrap().clone();
                match handler {
                    Some(h) => h(&surface, phase, actor.as_deref()),
                    // Not registered yet (app still booting) — buffer, so a
                    // window opened during startup still gets its Open.
                    None => {
                        let mut pend = inner.pending_lifecycle.lock().unwrap();
                        if pend.len() < 64 {
                            pend.push((surface, phase, actor));
                        }
                    }
                }
            }
        }
    }
}

/// D195: what pvosd reports for [`AppConn::admin_install_app`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInstalled {
    pub app_id: String,
    pub pubkey_hex: String,
    pub region: String,
    /// The pinned `integrity.ui_root`; `None` when no `ui/` was sent.
    pub ui_root: Option<String>,
    /// The live pvfsd's wire protocol, for the D63 install warning.
    pub pvfs_proto: u32,
}

/// An attached Channel-2 session with `pvosd`.
pub struct AppConn {
    inner: Arc<Inner>,
    context: Context,
}

/// Attach to the control socket (doc 04 §3): answer the challenge with the
/// app key, receive `Ready{context}`, and start the session reader.
pub fn connect<F>(control_socket: &Path, pubkey: &[u8], sign: F) -> Result<AppConn>
where
    F: FnOnce(&[u8; 32]) -> Vec<u8>,
{
    let mut stream = UnixStream::connect(control_socket)?;
    let (nonce, instance_id, expiry_ms) = match read_frame::<_, ServerMsg>(&mut stream)? {
        Some(ServerMsg::Challenge {
            nonce,
            instance_id,
            expiry_ms,
        }) => (
            hex::decode(&nonce).map_err(|_| SdkError::Protocol("nonce not hex".into()))?,
            instance_id,
            expiry_ms,
        ),
        other => return Err(unexpected("Challenge", other)),
    };
    let digest = auth_digest(&nonce, &instance_id, expiry_ms);
    write_frame(
        &mut stream,
        &ClientMsg::Auth {
            pubkey: hex::encode(pubkey),
            sig: hex::encode(sign(&digest)),
        },
    )?;
    let context = match read_frame::<_, ServerMsg>(&mut stream)? {
        Some(ServerMsg::Ready { context }) => context,
        Some(ServerMsg::Error { code, message, .. }) => {
            return Err(SdkError::Server { code, message })
        }
        other => return Err(unexpected("Ready", other)),
    };

    let inner = Arc::new(Inner {
        writer: Mutex::new(stream.try_clone()?),
        pending: Mutex::new(HashMap::new()),
        events: Mutex::new(HashMap::new()),
        on_call: Mutex::new(None),
        on_cap: Mutex::new(None),
        on_ui_event: Mutex::new(None),
        on_lifecycle: Mutex::new(None),
        on_park: Mutex::new(None),
        pending_lifecycle: Mutex::new(Vec::new()),
        ui_tx: Mutex::new(None),
        outbox: (Mutex::new(Outbox::default()), Condvar::new()),
        closed: (Mutex::new(false), Condvar::new()),
        next_req: AtomicU64::new(1),
        conn_failures: AtomicU64::new(0),
        calls_inflight: AtomicU64::new(0),
    });
    {
        // The push sender: one thread drains the outbox so view-model
        // pushes never block app threads (D43).
        let inner = inner.clone();
        std::thread::spawn(move || push_sender(inner));
    }
    {
        // The UI worker: one thread, so the app observes clicks in the order
        // the desktop sent them (see `ui_worker`).
        let (ui_tx, ui_rx) = mpsc::channel::<UiJob>();
        *inner.ui_tx.lock().unwrap() = Some(ui_tx);
        let worker = inner.clone();
        std::thread::spawn(move || ui_worker(ui_rx, worker));
    }
    {
        let inner = inner.clone();
        std::thread::spawn(move || reader_loop(stream, inner));
    }
    Ok(AppConn { inner, context })
}

/// Route every inbound frame: correlated responses wake their requester;
/// pushes dispatch to handlers on fresh threads.
fn reader_loop(mut stream: UnixStream, inner: Arc<Inner>) {
    while let Ok(Some(raw)) = read_frame::<_, serde_json::Value>(&mut stream) {
        // D47: an unknown TYPE TAG is version skew, not death — log and
        // continue (framing/JSON corruption still ends the loop). D50:
        // only the unknown tag skips — a KNOWN message that won't decode
        // is a broken contract (new fields ship optional); it ends the
        // loop like corruption, and the dead-connection machinery turns
        // that into a supervised self-heal instead of a silent mask.
        let tag = raw
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("<untagged>")
            .to_string();
        let msg: ServerMsg = match serde_json::from_value(raw) {
            Ok(m) => m,
            // serde_json names exactly the unrecognized-tag case
            // "unknown variant …"; anything else is a known tag with an
            // undecodable body.
            Err(e) if e.to_string().starts_with("unknown variant") => {
                pv_warn!("pvos.sdk.message_skipped", tag = &tag, error = content(&e);
                    "pvos-sdk: unknown '{tag}' server message (version skew?) — skipped: {e}");
                continue;
            }
            Err(e) => {
                pv_error!(
                    "pvos.sdk.message_undecodable", tag = &tag, error = content(&e);
                    "pvos-sdk: undecodable '{tag}' server message (broken contract) — closing: {e}"
                );
                break;
            }
        };
        match msg {
            ServerMsg::Context { req_id, .. }
            | ServerMsg::Ack { req_id }
            | ServerMsg::Capabilities { req_id, .. }
            | ServerMsg::Services { req_id, .. }
            | ServerMsg::CallResult { req_id, .. }
            | ServerMsg::Granted { req_id, .. }
            | ServerMsg::AdminState { req_id, .. }
            | ServerMsg::AppInstalled { req_id, .. }
            | ServerMsg::InviteCreated { req_id, .. }
            | ServerMsg::InviteList { req_id, .. }
            | ServerMsg::MemberList { req_id, .. }
            | ServerMsg::MemberImpact { req_id, .. }
            | ServerMsg::DnsSetting { req_id, .. }
            | ServerMsg::NotifyRouting { req_id, .. }
            | ServerMsg::MountsReport { req_id, .. }
            | ServerMsg::TokenCreated { req_id, .. }
            | ServerMsg::TokenList { req_id, .. }
            | ServerMsg::AppMethods { req_id, .. }
            | ServerMsg::SessionList { req_id, .. }
            | ServerMsg::Revoked { req_id, .. }
            | ServerMsg::Notifications { req_id, .. }
            | ServerMsg::Paired { req_id, .. }
            | ServerMsg::LogDestinations { req_id, .. }
            | ServerMsg::Error {
                req_id: Some(req_id),
                ..
            } => {
                if let Some(tx) = inner.pending.lock().unwrap().remove(&req_id) {
                    let _ = tx.send(msg);
                }
            }
            ServerMsg::IncomingServiceCall {
                call_id,
                from: _,
                service,
                method,
                args,
            } => {
                // D59: counted HERE, on the reader — a ParkHint behind this
                // call in the same channel must find it already in flight.
                inner.calls_inflight.fetch_add(1, Ordering::SeqCst);
                let handler = inner.on_call.lock().unwrap().clone();
                let inner = inner.clone();
                std::thread::spawn(move || {
                    // Decrement on every exit, panicking handlers included —
                    // a stuck counter would make the app unparkable forever.
                    struct Inflight(Arc<Inner>);
                    impl Drop for Inflight {
                        fn drop(&mut self) {
                            self.0.calls_inflight.fetch_sub(1, Ordering::SeqCst);
                        }
                    }
                    let _guard = Inflight(inner.clone());
                    let outcome = match handler {
                        Some(h) => h(&service, &method, args),
                        None => CallOutcome::Err {
                            code: "no_handler".into(),
                            message: "app registered no call handler".into(),
                        },
                    };
                    let _ = inner.send(&ClientMsg::ServiceReply { call_id, outcome });
                });
            }
            ServerMsg::ParkHint => {
                // D45: consult the app; no handler = demand-driven app =
                // park by default. Runs on its own thread — the handler
                // may flush state (a snapshot write) before agreeing.
                // D59: a service call in flight vetoes the park regardless
                // of the consult — exit(0) would strand delivered work.
                let handler = inner.on_park.lock().unwrap().clone();
                let inner = inner.clone();
                std::thread::spawn(move || {
                    let busy = inner.calls_inflight.load(Ordering::SeqCst);
                    if busy > 0 {
                        pv_info!("pvos.sdk.park_declined", inflight = busy;
                            "pvos-sdk: declining park — {busy} service call(s) in flight");
                        return;
                    }
                    let ok = handler.map(|h| h()).unwrap_or(true);
                    if ok {
                        // Re-check: a fire may have arrived during the
                        // consult (it can flush state for a while).
                        if inner.calls_inflight.load(Ordering::SeqCst) > 0 {
                            pv_info!(
                                "pvos.sdk.park_declined";
                                "pvos-sdk: declining park — a service call arrived mid-consult"
                            );
                            return;
                        }
                        pv_notice!("pvos.sdk.parking";
                            "pvos-sdk: parking (idle) — supervision respawns on next demand");
                        std::process::exit(0);
                    }
                });
            }
            ServerMsg::ServiceEvent { topic, payload, provider } => {
                // PVOS D254: pvosd sends only what this app subscribed to, so
                // an event no provider-named handler takes is its own topic's.
                let events = inner.events.lock().unwrap();
                let handler = provider
                    .and_then(|p| events.get(&(Some(p.0), topic.clone())).cloned())
                    .or_else(|| events.get(&(None, topic.clone())).cloned());
                drop(events);
                if let Some(h) = handler {
                    std::thread::spawn(move || h(payload));
                }
            }
            ServerMsg::CapabilityChanged { change, capability } => {
                let handler = inner.on_cap.lock().unwrap().clone();
                if let Some(h) = handler {
                    std::thread::spawn(move || h(change, capability));
                }
            }
            ServerMsg::UiEvent { surface, action, payload, actor } => {
                inner.queue_ui(UiJob::Event {
                    surface,
                    action,
                    payload,
                    actor,
                });
            }
            ServerMsg::UiLifecycle { surface, phase, actor } => {
                inner.queue_ui(UiJob::Lifecycle { surface, phase, actor });
            }
            // Handshake frames and uncorrelated errors: nothing to route.
            ServerMsg::Challenge { .. } | ServerMsg::Ready { .. } => {}
            ServerMsg::Error { req_id: None, .. } => {
                pv_warn!("pvos.sdk.uncorrelated_error", error = content(format!("{msg:?}"));
                    "pvos-sdk: uncorrelated error: {msg:?}");
            }
        }
    }
    // Connection down: wake every waiter with a hangup, then release anyone
    // parked in `wait_closed` so the process can exit instead of lingering.
    inner.pending.lock().unwrap().clear();
    let (done, cv) = &inner.closed;
    *done.lock().unwrap() = true;
    cv.notify_all();
}

impl AppConn {
    /// The context received at attach.
    pub fn context(&self) -> &Context {
        &self.context
    }

    fn request<B>(&self, build: B) -> Result<ServerMsg>
    where
        B: FnOnce(u64) -> ClientMsg,
    {
        self.request_within(REQUEST_TTL, build)
    }

    /// Like [`Self::request`] with a caller-chosen wait — for requests whose
    /// reply waits on a HUMAN (an invite delegation being approved on a
    /// companion), where 35s would abandon the code mid-approval.
    fn request_within<B>(&self, ttl: Duration, build: B) -> Result<ServerMsg>
    where
        B: FnOnce(u64) -> ClientMsg,
    {
        self.inner.request_within(ttl, build)
    }

    /// Re-fetch the current context (caps may have changed since attach).
    pub fn get_context(&mut self) -> Result<Context> {
        match self.request(|req_id| ClientMsg::GetContext { req_id })? {
            ServerMsg::Context { context, .. } => {
                self.context = context.clone();
                Ok(context)
            }
            other => Err(unexpected("Context", Some(other))),
        }
    }

    /// This app's currently-effective capabilities (live).
    pub fn list_capabilities(&self) -> Result<Vec<Capability>> {
        match self.request(|req_id| ClientMsg::ListCapabilities { req_id })? {
            ServerMsg::Capabilities { capabilities, .. } => Ok(capabilities),
            other => Err(unexpected("Capabilities", Some(other))),
        }
    }

    // ── provider surface ────────────────────────────────────────────────

    /// Register the handler for incoming service calls. Set this BEFORE
    /// `publish` so no call finds the app handler-less.
    pub fn on_call<H>(&self, handler: H)
    where
        H: Fn(&str, &str, Value) -> CallOutcome + Send + Sync + 'static,
    {
        *self.inner.on_call.lock().unwrap() = Some(Arc::new(handler));
    }

    /// Advertise a service this app offers (doc 06 §2).
    pub fn publish(&self, decl: pvos_proto::manifest::ServiceDecl) -> Result<()> {
        match self.request(|req_id| ClientMsg::PublishService { req_id, decl })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    pub fn unpublish(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        match self.request(|req_id| ClientMsg::UnpublishService { req_id, name })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// Emit an event on one of this provider's topics (ephemeral, D5).
    pub fn emit(&self, topic: &str, payload: Value) -> Result<()> {
        let topic = topic.to_string();
        match self.request(|req_id| ClientMsg::EmitEvent {
            req_id,
            topic,
            payload,
        })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    // ── consumer surface ────────────────────────────────────────────────

    pub fn discover(&self, query: Option<&str>) -> Result<Vec<ServiceInfo>> {
        let query = query.map(str::to_string);
        match self.request(|req_id| ClientMsg::DiscoverServices { req_id, query })? {
            ServerMsg::Services { services, .. } => Ok(services),
            other => Err(unexpected("Services", Some(other))),
        }
    }

    /// Call a service; blocks until the routed reply (or a typed error —
    /// `denied` / `not_found` / `unavailable` / `timeout`).
    pub fn call(
        &self,
        provider: &ProviderId,
        service: &str,
        method: &str,
        args: Value,
    ) -> Result<Value> {
        let (provider, service, method) = (provider.clone(), service.to_string(), method.into());
        match self.request(|req_id| ClientMsg::CallService {
            req_id,
            provider,
            service,
            method,
            args,
            version: None,
        })? {
            ServerMsg::CallResult { outcome, .. } => match outcome {
                CallOutcome::Ok { value } => Ok(value),
                CallOutcome::Err { code, message } => Err(SdkError::Server { code, message }),
            },
            other => Err(unexpected("CallResult", Some(other))),
        }
    }

    /// Subscribe to one of this app's own topics; `handler` runs for each
    /// event (its own thread).
    pub fn subscribe<H>(&self, topic: &str, handler: H) -> Result<()>
    where
        H: Fn(Value) + Send + Sync + 'static,
    {
        self.subscribe_as(None, topic, handler)
    }

    /// PVOS D254 — subscribe to `provider`'s `topic` (an async job's
    /// `job/<id>`, a provider's announcements). Needs a `Service` capability
    /// on that provider; refused `denied` otherwise.
    pub fn subscribe_to<H>(&self, provider: &ProviderId, topic: &str, handler: H) -> Result<()>
    where
        H: Fn(Value) + Send + Sync + 'static,
    {
        self.subscribe_as(Some(provider.clone()), topic, handler)
    }

    fn subscribe_as<H>(&self, provider: Option<ProviderId>, topic: &str, handler: H) -> Result<()>
    where
        H: Fn(Value) + Send + Sync + 'static,
    {
        let key = (provider.as_ref().map(|p| p.0.clone()), topic.to_string());
        self.inner.events.lock().unwrap().insert(key.clone(), Arc::new(handler));
        let topic = topic.to_string();
        match self.request(|req_id| ClientMsg::Subscribe { req_id, topic, provider }) {
            Ok(ServerMsg::Ack { .. }) => Ok(()),
            Ok(other) => {
                self.inner.events.lock().unwrap().remove(&key);
                Err(unexpected("Ack", Some(other)))
            }
            Err(e) => {
                self.inner.events.lock().unwrap().remove(&key);
                Err(e)
            }
        }
    }

    pub fn unsubscribe(&self, topic: &str) -> Result<()> {
        self.unsubscribe_as(None, topic)
    }

    /// PVOS D254 — the opposite of [`Self::subscribe_to`].
    pub fn unsubscribe_from(&self, provider: &ProviderId, topic: &str) -> Result<()> {
        self.unsubscribe_as(Some(provider.clone()), topic)
    }

    fn unsubscribe_as(&self, provider: Option<ProviderId>, topic: &str) -> Result<()> {
        self.inner.events.lock().unwrap().remove(&(provider.as_ref().map(|p| p.0.clone()), topic.to_string()));
        let topic = topic.to_string();
        match self.request(|req_id| ClientMsg::Unsubscribe { req_id, topic, provider })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// Register a callback for `CapabilityChanged` pushes.
    pub fn on_capability_changed<H>(&self, handler: H)
    where
        H: Fn(CapChange, Capability) + Send + Sync + 'static,
    {
        *self.inner.on_cap.lock().unwrap() = Some(Arc::new(handler));
    }

    // ── UI surface (Mode B, doc 08 §4) ──────────────────────────────────

    /// Render (or re-render) a surface with a view-model — every session
    /// with the window open receives it.
    pub fn push_view_model(&self, surface: &str, view_model: pvos_proto::ViewModel) -> Result<()> {
        self.push_view(surface, view_model, None)
    }

    /// Render a surface for ONE session (D39): only the desktop behind
    /// `actor` receives it — per-viewer navigation on a shared surface.
    pub fn push_view_model_for(
        &self,
        surface: &str,
        actor: &str,
        view_model: pvos_proto::ViewModel,
    ) -> Result<()> {
        self.push_view(surface, view_model, Some(actor.to_string()))
    }

    /// Enqueue a view for the outbox sender (D43): replaces any not-yet-
    /// sent view for the same (surface, actor) — stale frames are
    /// worthless once a newer render exists — and NEVER touches the
    /// socket, so no app thread can wedge in send() behind a peer that
    /// stopped reading. `Ok` means queued, not delivered; delivery
    /// failures are logged by the sender and healed by the next render.
    fn push_view(
        &self,
        surface: &str,
        view_model: pvos_proto::ViewModel,
        actor: Option<String>,
    ) -> Result<()> {
        let key = (surface.to_string(), actor);
        let (lock, cv) = &self.inner.outbox;
        let mut ob = lock.lock().unwrap();
        if ob.latest.insert(key.clone(), view_model).is_none() {
            ob.order.push_back(key);
        }
        cv.notify_one();
        Ok(())
    }

    /// Append lines to a `log` component on a surface (streaming, D2).
    pub fn append_log(&self, surface: &str, component_id: &str, lines: Vec<String>) -> Result<()> {
        let (surface, component_id) = (surface.to_string(), component_id.to_string());
        match self.request(|req_id| ClientMsg::AppendLog {
            req_id,
            surface,
            component_id,
            lines,
        })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// Park until `pvosd` closes the session (shutdown, or this app being
    /// stopped/restarted).
    ///
    /// This is how a service app ends its `main`. Parking on a sleep loop
    /// instead leaves a ghost process behind on every restart — still holding
    /// the app's forest subtree, still on its schedules — which is both a leak
    /// and a two-writers hazard.
    pub fn wait_closed(&self) {
        let (done, cv) = &self.inner.closed;
        let mut ended = done.lock().unwrap();
        while !*ended {
            ended = cv.wait(ended).unwrap();
        }
    }

    /// Register a handler for UI events on this app's surfaces.
    pub fn on_ui_event<H>(&self, handler: H)
    where
        H: Fn(&str, &str, Value, Option<&str>) + Send + Sync + 'static,
    {
        *self.inner.on_ui_event.lock().unwrap() = Some(Arc::new(handler));
    }

    /// Register a handler for surface window lifecycle events. Lifecycle
    /// pushes that arrived before registration (a window opened while the
    /// app was booting) are delivered immediately, in order.
    /// D45: register the park consult — return false to decline while work
    /// is in flight; flush dirty state before returning true (exit follows).
    /// Apps that never register park by default (demand-driven is the norm).
    pub fn on_park<H>(&self, handler: H)
    where
        H: Fn() -> bool + Send + Sync + 'static,
    {
        *self.inner.on_park.lock().unwrap() = Some(Arc::new(handler));
    }

    pub fn on_lifecycle<H>(&self, handler: H)
    where
        H: Fn(&str, pvos_proto::UiPhase, Option<&str>) + Send + Sync + 'static,
    {
        let handler: LifecycleHandler = Arc::new(handler);
        *self.inner.on_lifecycle.lock().unwrap() = Some(handler);
        // Replay through the same queue rather than a side thread: the
        // buffered pushes arrived first, so they must be delivered first.
        let pending: Vec<_> = self.inner.pending_lifecycle.lock().unwrap().drain(..).collect();
        for (surface, phase, actor) in pending {
            self.inner.queue_ui(UiJob::Lifecycle { surface, phase, actor });
        }
    }

    /// Request a capability at runtime → owner consent (blocks on the outcome).
    /// Returns the grant id on approval; a typed `denied`/`parked` error else.
    pub fn request_capability(&self, capability: Capability, reason: &str) -> Result<String> {
        let reason = reason.to_string();
        match self.request(|req_id| ClientMsg::RequestCapability {
            req_id,
            capability,
            reason,
        })? {
            ServerMsg::Granted { grant_id, .. } => Ok(grant_id),
            other => Err(unexpected("Granted", Some(other))),
        }
    }

    // ── delegation (doc 04 §4.2 helper flow) ───────────────────────────

    /// Delegate a narrowed capability to another app: pre-flight over
    /// Channel 2 (`pvosd` checks attenuation + this app's depth budget),
    /// author + **sign** the record into this app's own grants subtree via
    /// Channel 1, then notify `pvosd` to refold (affected apps get
    /// `CapabilityChanged`). Returns the new grant id.
    pub fn delegate<F>(
        &self,
        pvfs: &mut pvfs_client_core::Client,
        subject: Subject,
        capability: Capability,
        depth: Depth,
        sign: F,
    ) -> Result<GrantId>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        let grants_root = self
            .context
            .grants_root
            .clone()
            .ok_or_else(|| SdkError::Protocol("context has no grants_root".into()))?;
        // Pre-flight (advisory but fail-fast; the broker re-validates on fold).
        {
            let capability = capability.clone();
            match self.request(|req_id| ClientMsg::ValidateDelegation {
                req_id,
                capability,
                depth,
            })? {
                ServerMsg::Ack { .. } => {}
                other => return Err(unexpected("Ack", Some(other))),
            }
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let seq = self.inner.next_req.fetch_add(1, Ordering::Relaxed);
        let id = GrantId(format!("d-{now_ms:x}-{seq:x}"));
        let record = GrantRecord::Grant(Grant {
            id: id.clone(),
            subject,
            capability,
            issuer: Issuer::App(self.context.app_id.clone()),
            redelegation_depth: depth,
            expiry: None,
            issued_at: now_ms,
        });
        let body =
            serde_json::to_vec(&record).map_err(|e| SdkError::Protocol(e.to_string()))?;
        pvfs.add_node(&grants_root, &id.0, TYPE_GRANT_RECORD, &body, sign)
            .map_err(|e| SdkError::Protocol(format!("append delegation: {e}")))?;
        self.notify_grants_changed()?;
        Ok(id)
    }

    /// Revoke a delegation this app issued: author the signed revoke record
    /// into its grants subtree, then refold.
    pub fn revoke_delegation<F>(
        &self,
        pvfs: &mut pvfs_client_core::Client,
        grant: GrantId,
        sign: F,
    ) -> Result<()>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        let grants_root = self
            .context
            .grants_root
            .clone()
            .ok_or_else(|| SdkError::Protocol("context has no grants_root".into()))?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let record = GrantRecord::Revoke {
            grant: grant.clone(),
            at: now_ms,
        };
        let body =
            serde_json::to_vec(&record).map_err(|e| SdkError::Protocol(e.to_string()))?;
        let label = format!("r-{}", grant.0);
        pvfs.add_node(&grants_root, &label, TYPE_GRANT_RECORD, &body, sign)
            .map_err(|e| SdkError::Protocol(format!("append revoke: {e}")))?;
        self.notify_grants_changed()
    }

    /// Tell `pvosd` this app changed its grants subtree — triggers a refold
    /// and `CapabilityChanged` pushes to affected apps.
    pub fn notify_grants_changed(&self) -> Result<()> {
        match self.request(|req_id| ClientMsg::NotifyGrantsChanged { req_id })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    // ── admin surface (owner sessions, doc 04 §4.5) ─────────────────────
    // These succeed only when the connection was attached with the OWNER
    // key; app sessions get `forbidden`.

    pub fn admin_install(
        &self,
        app_id: &str,
        pubkey_hex: &str,
        manifest_json: Option<String>,
    ) -> Result<()> {
        let (app_id, pubkey) = (app_id.to_string(), pubkey_hex.to_string());
        match self.request(|req_id| ClientMsg::AdminInstall {
            req_id,
            app_id,
            pubkey,
            manifest: manifest_json,
        })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// D195: the whole install, done by pvosd — register, import `ui` into
    /// the forest and pin `integrity.ui_root`, store the manifest — the same
    /// install an offline CLI runs. A pre-D195 pvosd skips this without
    /// answering: check [`Self::admin_daemon_ops`] for
    /// [`pvos_proto::OP_INSTALL_APP`] first.
    pub fn admin_install_app(
        &self,
        app_id: &str,
        pubkey_hex: &str,
        manifest_json: String,
        ui: Option<Vec<pvos_proto::UiFile>>,
        take_over: bool,
    ) -> Result<AppInstalled> {
        let (app_id, pubkey) = (app_id.to_string(), pubkey_hex.to_string());
        // Longer than a plain request: every imported file is an owner
        // signature, which in production is a companion round trip.
        match self.request_within(Duration::from_secs(120), |req_id| ClientMsg::AdminInstallApp {
            req_id,
            app_id,
            pubkey,
            manifest: manifest_json,
            ui,
            take_over,
        })? {
            ServerMsg::AppInstalled {
                app_id,
                pubkey_hex,
                region,
                ui_root,
                pvfs_proto,
                ..
            } => Ok(AppInstalled {
                app_id,
                pubkey_hex,
                region,
                ui_root,
                pvfs_proto,
            }),
            other => Err(unexpected("AppInstalled", Some(other))),
        }
    }

    /// D195: the admin ops this pvosd has beyond the original set — empty
    /// from a pre-D195 pvosd.
    pub fn admin_daemon_ops(&self) -> Result<Vec<String>> {
        match self.request(|req_id| ClientMsg::AdminList { req_id })? {
            ServerMsg::AdminState { daemon_ops, .. } => Ok(daemon_ops),
            other => Err(unexpected("AdminState", Some(other))),
        }
    }

    pub fn admin_grant(
        &self,
        subject: Subject,
        capability: Capability,
        depth: Depth,
        expiry: Option<u64>,
    ) -> Result<String> {
        match self.request(|req_id| ClientMsg::AdminGrant {
            req_id,
            subject,
            capability,
            depth,
            expiry,
        })? {
            ServerMsg::Granted { grant_id, .. } => Ok(grant_id),
            other => Err(unexpected("Granted", Some(other))),
        }
    }

    pub fn admin_revoke(&self, grant_id: &str) -> Result<()> {
        let grant_id = grant_id.to_string();
        match self.request(|req_id| ClientMsg::AdminRevoke { req_id, grant_id })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    pub fn admin_list(
        &self,
    ) -> Result<(Vec<pvos_proto::AdminAppInfo>, Vec<pvos_proto::AdminGrantInfo>)> {
        match self.request(|req_id| ClientMsg::AdminList { req_id })? {
            ServerMsg::AdminState { apps, records, .. } => Ok((apps, records)),
            other => Err(unexpected("AdminState", Some(other))),
        }
    }

    pub fn admin_start_app(&self, app_id: &str) -> Result<()> {
        let app_id = app_id.to_string();
        match self.request(|req_id| ClientMsg::AdminStartApp { req_id, app_id })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// Mint a member invite (D18). Blocks while a member companion approves
    /// the delegation — up to ~5 minutes (the server's relay age-out), not
    /// the normal request TTL. Returns `(invite_id, code, expires_ms)`; the
    /// code appears here ONCE and is stored only as a hash.
    pub fn admin_invite_create(
        &self,
        member: &str,
        email: &str,
        role: &str,
        ttl_ms: Option<u64>,
    ) -> Result<(String, String, u64, bool)> {
        let (member, email, role) = (member.to_string(), email.to_string(), role.to_string());
        match self.request_within(Duration::from_secs(290), |req_id| {
            ClientMsg::AdminInviteCreate { req_id, member, email, role, ttl_ms }
        })? {
            ServerMsg::InviteCreated { invite_id, code, expires_ms, emailed, .. } => {
                Ok((invite_id, code, expires_ms, emailed))
            }
            other => Err(unexpected("InviteCreated", Some(other))),
        }
    }

    /// Set a member's contact email on the LIVE daemon (always unverified).
    pub fn admin_member_set_email(&self, member: &str, email: &str) -> Result<()> {
        let (member, email) = (member.to_string(), email.to_string());
        match self.request(|req_id| ClientMsg::AdminMemberSetEmail { req_id, member, email })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// D36: mint a rekey invite for an existing member. Same reply shape as
    /// admin_invite_create; waits on the companion relay the same way.
    pub fn admin_member_rekey(&self, member: &str) -> Result<(String, String, u64, bool)> {
        let member = member.to_string();
        match self.request_within(Duration::from_secs(290), |req_id| {
            ClientMsg::AdminMemberRekey { req_id, member }
        })? {
            ServerMsg::InviteCreated { invite_id, code, expires_ms, emailed, .. } => {
                Ok((invite_id, code, expires_ms, emailed))
            }
            other => Err(unexpected("InviteCreated", Some(other))),
        }
    }

    /// As [`admin_invite_create`] with the D36 reattach warning included:
    /// (invite_id, code, expires_ms, emailed, reattach_warning).
    #[allow(clippy::type_complexity)]
    pub fn admin_invite_create_flagged(
        &self,
        member: &str,
        email: &str,
        role: &str,
        ttl_ms: Option<u64>,
    ) -> Result<(String, String, u64, bool, bool)> {
        let (member, email, role) = (member.to_string(), email.to_string(), role.to_string());
        match self.request_within(Duration::from_secs(290), |req_id| {
            ClientMsg::AdminInviteCreate { req_id, member, email, role, ttl_ms }
        })? {
            ServerMsg::InviteCreated { invite_id, code, expires_ms, emailed, reattach_warning, .. } => {
                Ok((invite_id, code, expires_ms, emailed, reattach_warning))
            }
            other => Err(unexpected("InviteCreated", Some(other))),
        }
    }

    pub fn admin_member_archive_data(&self, member: &str) -> Result<()> {
        let member = member.to_string();
        match self.request(|req_id| ClientMsg::AdminMemberArchiveData { req_id, member })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    pub fn admin_member_set_role(&self, member: &str, role: &str) -> Result<()> {
        let (member, role) = (member.to_string(), role.to_string());
        match self.request(|req_id| ClientMsg::AdminMemberSetRole { req_id, member, role })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// PVOS D259: set the member actions `member` may take in `app_id` (the
    /// whole set; empty clears it).
    pub fn admin_member_set_app_actions(&self, member: &str, app_id: &str, actions: &[String]) -> Result<()> {
        let (member, app_id, actions) = (member.to_string(), app_id.to_string(), actions.to_vec());
        match self.request(|req_id| ClientMsg::AdminMemberSetAppActions { req_id, member, app_id, actions })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// Share an installed app with a role (D18 slice 4). Refused for
    /// admin-only apps. Returns the share's grant id.
    pub fn admin_share(&self, app_id: &str, role: &str) -> Result<String> {
        let (app_id, role) = (app_id.to_string(), role.to_string());
        match self.request(|req_id| ClientMsg::AdminShare { req_id, app_id, role })? {
            ServerMsg::Granted { grant_id, .. } => Ok(grant_id),
            other => Err(unexpected("Granted", Some(other))),
        }
    }

    /// Revoke a share created by [`Self::admin_share`].
    pub fn admin_unshare(&self, app_id: &str, role: &str) -> Result<()> {
        let (app_id, role) = (app_id.to_string(), role.to_string());
        match self.request(|req_id| ClientMsg::AdminUnshare { req_id, app_id, role })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// Every member (D18 slice 5).
    pub fn admin_member_list(&self) -> Result<Vec<pvos_proto::MemberInfo>> {
        match self.request(|req_id| ClientMsg::AdminMemberList { req_id })? {
            ServerMsg::MemberList { members, .. } => Ok(members),
            other => Err(unexpected("MemberList", Some(other))),
        }
    }

    /// PVOS D262: save the DNS setting for PVOS apps (the record's JSON), or
    /// clear it with `None`.
    pub fn admin_dns_set(&self, config: Option<Value>) -> Result<()> {
        match self.request(|req_id| ClientMsg::AdminDnsSet { req_id, config })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// PVOS D262: (the DNS setting for apps, the host's resolvers, the notice).
    pub fn admin_dns_show(&self) -> Result<(Option<Value>, Vec<String>, String)> {
        match self.request(|req_id| ClientMsg::AdminDnsShow { req_id })? {
            ServerMsg::DnsSetting { config, host_resolvers, notice, .. } => Ok((config, host_resolvers, notice)),
            other => Err(unexpected("DnsSetting", Some(other))),
        }
    }

    /// PVOS D290: the notification routing, or `None` when none is saved.
    pub fn admin_notify_routing_show(&self) -> Result<Option<Value>> {
        match self.request(|req_id| ClientMsg::AdminNotifyRoutingShow { req_id })? {
            ServerMsg::NotifyRouting { routing, .. } => Ok(routing),
            other => Err(unexpected("NotifyRouting", Some(other))),
        }
    }

    /// PVOS D290: save the notification routing. The desktop's Settings op
    /// calls the same daemon function.
    pub fn admin_notify_routing_set(&self, routing: Value) -> Result<()> {
        match self.request(|req_id| ClientMsg::AdminNotifyRoutingSet { req_id, routing })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// PVOS D290: one mounts, forest, instance, or replica operation. `show`
    /// returns the listing; a change returns the sentence Settings would toast.
    pub fn admin_mounts(
        &self,
        action: &str,
        args: Value,
    ) -> Result<(String, Option<pvos_proto::desktop::MountsView>)> {
        let action = action.to_string();
        match self.request(|req_id| ClientMsg::AdminMounts { req_id, action, args })? {
            ServerMsg::MountsReport { summary, view, .. } => Ok((summary, view)),
            other => Err(unexpected("MountsReport", Some(other))),
        }
    }

    /// PVOS D290: mint a scoped token. Blocks while the companion approves,
    /// the same wait as an invite. The secret is in the reply once.
    pub fn admin_token_create(
        &self,
        label: &str,
        operations: Vec<String>,
        app: Option<String>,
        ttl_ms: u64,
    ) -> Result<(String, String, u64)> {
        let label = label.to_string();
        match self.request_within(Duration::from_secs(290), |req_id| ClientMsg::AdminTokenCreate {
            req_id,
            label,
            operations,
            app,
            ttl_ms,
        })? {
            ServerMsg::TokenCreated { token_id, secret, expires_ms, .. } => Ok((token_id, secret, expires_ms)),
            other => Err(unexpected("TokenCreated", Some(other))),
        }
    }

    /// PVOS D290: the tokens, without secrets.
    pub fn admin_token_list(&self) -> Result<Vec<pvos_proto::ApiTokenInfo>> {
        match self.request(|req_id| ClientMsg::AdminTokenList { req_id })? {
            ServerMsg::TokenList { tokens, .. } => Ok(tokens),
            other => Err(unexpected("TokenList", Some(other))),
        }
    }

    /// PVOS D290: API methods installed apps declare.
    pub fn admin_app_methods(&self) -> Result<Vec<pvos_proto::ApiMethodInfo>> {
        match self.request(|req_id| ClientMsg::AdminAppMethods { req_id })? {
            ServerMsg::AppMethods { methods, .. } => Ok(methods),
            other => Err(unexpected("AppMethods", Some(other))),
        }
    }

    /// PVOS D290: call one declared API method. A method that is only
    /// published is refused. A companion-signed method waits here for the
    /// approval, the same wait as minting a token.
    pub fn admin_app_call(
        &self,
        provider: Option<&str>,
        service: &str,
        method: &str,
        args: Value,
    ) -> Result<Value> {
        let provider = provider.map(str::to_string);
        let service = service.to_string();
        let method = method.to_string();
        match self.request_within(Duration::from_secs(290), |req_id| ClientMsg::AdminAppCall {
            req_id,
            provider,
            service,
            method,
            args,
        })? {
            ServerMsg::CallResult { outcome, .. } => match outcome {
                CallOutcome::Ok { value } => Ok(value),
                CallOutcome::Err { code, message } => Err(SdkError::Server { code, message }),
            },
            ServerMsg::Error { code, message, .. } => Err(SdkError::Server { code, message }),
            other => Err(unexpected("CallResult", Some(other))),
        }
    }

    /// PVOS D290: end a token. Its next call fails.
    pub fn admin_token_revoke(&self, token_id: &str) -> Result<()> {
        let token_id = token_id.to_string();
        match self.request(|req_id| ClientMsg::AdminTokenRevoke { req_id, token_id })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// PVOS D262: resolve `name` by the owner's DNS setting for apps
    /// (`pvos.dns`, which needs a `Service` grant) → `{name, addresses, via,
    /// fell_back, nxdomain, note}`.
    pub fn resolve(&self, name: &str) -> Result<Value> {
        self.call(&ProviderId::pvos(), "pvos.dns", "resolve", serde_json::json!({ "name": name }))
    }

    /// PVOS D262: `host:port` → socket addresses, by PVOS's DNS setting —
    /// the shape `ureq::AgentBuilder::resolver` takes. Without the grant, or
    /// from a pvosd that does not know `pvos.dns`, it is the host's resolver,
    /// as before; a name that is not one is an error either way.
    pub fn socket_addrs(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        let (host, port) = split_netloc(netloc)?;
        match self.resolve(host) {
            Ok(v) => {
                let addrs: Vec<std::net::SocketAddr> = v["addresses"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()?.parse::<std::net::IpAddr>().ok()).collect::<Vec<_>>())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|ip| std::net::SocketAddr::new(ip, port))
                    .collect();
                if addrs.is_empty() {
                    let why = v["note"].as_str().unwrap_or("no address");
                    return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("{host}: {why}")));
                }
                Ok(addrs)
            }
            Err(SdkError::Server { code, message }) if code == "bad_args" => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, message))
            }
            Err(_) => (host, port).to_socket_addrs().map(|it| it.collect()),
        }
    }

    /// D67 C2: the remembered sign-ins (M9), as display data.
    pub fn admin_session_list(&self) -> Result<Vec<pvos_proto::SessionInfo>> {
        match self.request(|req_id| ClientMsg::AdminSessionList { req_id })? {
            ServerMsg::SessionList { sessions, .. } => Ok(sessions),
            other => Err(unexpected("SessionList", Some(other))),
        }
    }

    /// D67 C2: revoke one remembered session, or ALL when `id` is None —
    /// through the daemon, so it reaches the open browser. Returns how many
    /// were actually killed.
    pub fn admin_session_revoke(&self, id: Option<&str>) -> Result<u64> {
        let id = id.map(str::to_string);
        match self.request(|req_id| ClientMsg::AdminSessionRevoke { req_id, id })? {
            ServerMsg::Revoked { count, .. } => Ok(count),
            other => Err(unexpected("Revoked", Some(other))),
        }
    }

    /// D67 C2c: write the mail relay config + password through the daemon.
    #[allow(clippy::too_many_arguments)]
    pub fn admin_mail_setup(
        &self,
        host: &str,
        port: u16,
        security: &str,
        username: &str,
        password: &str,
        from: &str,
    ) -> Result<()> {
        let (host, security, username, password, from) = (
            host.to_string(),
            security.to_string(),
            username.to_string(),
            password.to_string(),
            from.to_string(),
        );
        match self.request(|req_id| ClientMsg::AdminMailSetup {
            req_id,
            host,
            port,
            security,
            username,
            password,
            from,
        })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// PVOS D222d: the log destinations, with health (`pvos logging`).
    pub fn admin_log_list(&self) -> Result<pvos_proto::desktop::LoggingView> {
        match self.request(|req_id| ClientMsg::AdminLogList { req_id })? {
            ServerMsg::LogDestinations { view, .. } => Ok(view),
            other => Err(unexpected("LogDestinations", Some(other))),
        }
    }

    /// PVOS D222d: add or replace a destination (`token`: None keeps it).
    pub fn admin_log_set(
        &self,
        original: Option<&str>,
        dest: &pvos_proto::desktop::LogDestinationEdit,
        token: Option<&str>,
    ) -> Result<()> {
        let (original, dest, token) = (original.map(str::to_string), dest.clone(), token.map(str::to_string));
        match self.request(|req_id| ClientMsg::AdminLogSet { req_id, original, dest, token })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    pub fn admin_log_remove(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        match self.request(|req_id| ClientMsg::AdminLogRemove { req_id, name })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// PVOS D222d: send one test event to `name` now.
    pub fn admin_log_test(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        match self.request(|req_id| ClientMsg::AdminLogTest { req_id, name })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// D67 C2c: the owner's notification inbox, from the daemon that writes it.
    pub fn admin_notify_list(&self) -> Result<Vec<pvos_proto::notify::Notification>> {
        match self.request(|req_id| ClientMsg::AdminNotifyList { req_id })? {
            ServerMsg::Notifications { items, .. } => Ok(items),
            other => Err(unexpected("Notifications", Some(other))),
        }
    }

    /// D67 C2c: dismiss one notification, or all when `id` is None.
    pub fn admin_notify_dismiss(&self, id: Option<&str>) -> Result<u64> {
        let id = id.map(str::to_string);
        match self.request(|req_id| ClientMsg::AdminNotifyDismiss { req_id, id })? {
            ServerMsg::Revoked { count, .. } => Ok(count),
            other => Err(unexpected("Revoked", Some(other))),
        }
    }

    /// D67 C2b: pair a companion through the daemon — it runs the handshake
    /// and writes the record. Returns (member, role, identity pubkey hex).
    pub fn admin_pair(
        &self,
        member: &str,
        server_name: &str,
        socket: &str,
        origins: Vec<String>,
    ) -> Result<(String, String, String)> {
        let (member, server_name, socket) =
            (member.to_string(), server_name.to_string(), socket.to_string());
        match self.request(|req_id| ClientMsg::AdminPair {
            req_id,
            member,
            server_name,
            socket,
            origins,
        })? {
            ServerMsg::Paired {
                member,
                role,
                identity_pubkey_hex,
                ..
            } => Ok((member, role, identity_pubkey_hex)),
            other => Err(unexpected("Paired", Some(other))),
        }
    }

    /// The removal impact report (§3''' warning): (live sessions, pending
    /// invites they signed, accounts their redeemed invites created).
    pub fn admin_member_inspect(
        &self,
        member: &str,
    ) -> Result<(usize, Vec<pvos_proto::InviteInfo>, Vec<String>)> {
        let member = member.to_string();
        match self.request(|req_id| ClientMsg::AdminMemberInspect { req_id, member })? {
            ServerMsg::MemberImpact { sessions, pending_invites, invited_members, .. } => {
                Ok((sessions, pending_invites, invited_members))
            }
            other => Err(unexpected("MemberImpact", Some(other))),
        }
    }

    /// Remove a membership (D18 slice 5). The caller has already shown the
    /// impact report and obtained a human confirmation.
    pub fn admin_member_remove(&self, member: &str) -> Result<()> {
        let member = member.to_string();
        match self.request(|req_id| ClientMsg::AdminMemberRemove { req_id, member })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    pub fn admin_invite_list(&self) -> Result<Vec<pvos_proto::InviteInfo>> {
        match self.request(|req_id| ClientMsg::AdminInviteList { req_id })? {
            ServerMsg::InviteList { invites, .. } => Ok(invites),
            other => Err(unexpected("InviteList", Some(other))),
        }
    }

    pub fn admin_invite_revoke(&self, invite_id: &str) -> Result<()> {
        let invite_id = invite_id.to_string();
        match self.request(|req_id| ClientMsg::AdminInviteRevoke { req_id, invite_id })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    pub fn admin_stop_app(&self, app_id: &str) -> Result<()> {
        let app_id = app_id.to_string();
        match self.request(|req_id| ClientMsg::AdminStopApp { req_id, app_id })? {
            ServerMsg::Ack { .. } => Ok(()),
            other => Err(unexpected("Ack", Some(other))),
        }
    }

    /// Open Channel 1: a `pvfs-client` connection to `pvfsd` **as the app
    /// key**. Reachable scope = exactly the ACLs the broker granted (explicit
    /// ACL, default-deny — doc 03 §1).
    pub fn pvfs<F>(&self, pubkey: &[u8], sign: F) -> Result<pvfs_client_core::Client>
    where
        F: FnOnce(&[u8; 32]) -> Vec<u8>,
    {
        pvfs_client_core::Client::connect_signed(Path::new(&self.context.pvfsd_socket), pubkey, sign)
            .map_err(|e| SdkError::Protocol(format!("pvfs connect: {e}")))
    }

    /// Close the session (also happens on drop).
    pub fn close(&self) {
        if let Ok(w) = self.inner.writer.lock() {
            let _ = w.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for AppConn {
    fn drop(&mut self) {
        self.close();
    }
}

/// `host:port`, `[v6]:port` → (host, port).
fn split_netloc(netloc: &str) -> std::io::Result<(&str, u16)> {
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("'{netloc}' is not host:port"));
    let (host, port) = netloc.rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    Ok((host.trim_start_matches('[').trim_end_matches(']'), port))
}

fn unexpected(want: &str, got: Option<ServerMsg>) -> SdkError {
    match got {
        None => SdkError::Protocol(format!("closed before {want}")),
        Some(m) => SdkError::Protocol(format!("expected {want}, got {m:?}")),
    }
}

#[cfg(test)]
mod d262_tests {
    use super::split_netloc;

    #[test]
    fn a_netloc_splits_into_host_and_port() {
        assert_eq!(split_netloc("logs.home.test:9187").unwrap(), ("logs.home.test", 9187));
        assert_eq!(split_netloc("[fd00::1]:443").unwrap(), ("fd00::1", 443));
        assert!(split_netloc("no-port").is_err());
        assert!(split_netloc("host:http").is_err());
    }
}
