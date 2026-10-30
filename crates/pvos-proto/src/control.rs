//! Channel-2 control-socket messages (doc 04 §3–§5).
//!
//! M1 subset: attach handshake (`Challenge` → `Auth` → `Ready{context}`) +
//! `GetContext`. M2 adds §4.2 capabilities (list/validate-delegation/notify +
//! `CapabilityChanged` push) and §4.3 services (publish/discover/call/route/
//! events). UI (§4.4) lands in M3; `RequestCapability` JIT consent too.
//!
//! Framing: `u32 length (LE) || JSON body` (see `frame`). Requests carry a
//! `req_id`; responses echo it; **push** frames (`IncomingServiceCall`,
//! `ServiceEvent`, `CapabilityChanged`) are server-initiated and carry their
//! own correlation (`call_id`/topic). Handshake messages have no `req_id`.
//! One long-lived, multiplexed connection per running app.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::behavior::{CallOutcome, ServiceInfo};
use crate::grant::{GrantRecord, Subject};
use crate::manifest::ServiceDecl;
use crate::{AppId, Capability, Depth, NodeId, ProviderId, Timestamp};

/// The `app_id` of an owner/admin session (doc 04 §4.5). Not installable as
/// a real app id (the `@` keeps it out of the normal namespace).
pub const ADMIN_APP_ID: &str = "@owner";

/// Shell↔App / Channel-2 contract version this crate speaks.
pub const API_VERSION: u32 = 1;

/// The digest an app signs to answer a `Challenge` (mirrors PVFS's
/// `auth_digest`, doc 04 §3 / PVFS doc 07): domain-separated SHA-256 over the
/// length-prefixed fields, so no field can bleed into another.
pub fn auth_digest(nonce: &[u8], instance_id: &str, expiry_ms: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"pvos:control-auth:v1:");
    h.update((nonce.len() as u64).to_le_bytes());
    h.update(nonce);
    h.update((instance_id.len() as u64).to_le_bytes());
    h.update(instance_id.as_bytes());
    h.update(expiry_ms.to_le_bytes());
    h.finalize().into()
}

/// The `HostContext` on the wire (doc 03 §6.3, doc 04 §3): everything an app
/// needs after attach — who it is, where its region is, where `pvfsd` lives,
/// and the capabilities currently effective for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub app_id: AppId,
    pub region_root: NodeId,
    /// The app's own `/apps/<id>/grants` subtree — where it authors
    /// delegations (doc 02 §2.1). Additive since M1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants_root: Option<NodeId>,
    pub pvfsd_socket: String,
    pub capabilities: Vec<Capability>,
    pub api_version: u32,
    /// PVOS D205: the running pvosd's build (`git describe`), on the
    /// OWNER's admin context only — `pvos version` reads it. Absent from an
    /// older daemon and from every app's context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pvosd_build: Option<String>,
}

/// App → `pvosd`. Internally tagged on `"type"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Answer the challenge: prove possession of a registered app key
    /// (or the owner/admin key, §4.5). No anonymous tier on this socket.
    Auth {
        pubkey: String, // hex
        sig: String,    // hex, over digest(nonce, instance_id, expiry_ms)
    },
    /// Re-fetch the current context (caps may have changed since attach).
    GetContext { req_id: u64 },

    // ── §4.2 capabilities (M2) ──────────────────────────────────────────
    /// This app's currently-effective capabilities (live, not attach-time).
    ListCapabilities { req_id: u64 },
    /// Pre-flight a delegation the app is about to author (doc 02 §3/§6):
    /// `pvosd` checks attenuation + the caller's depth budget. On `Ack`, the
    /// app signs + appends the record into its own `/apps/<id>/grants` via
    /// Channel 1, then sends `NotifyGrantsChanged`. (The signature never
    /// leaves the key holder — doc 04 §4.2's helper, restructured.)
    ValidateDelegation {
        req_id: u64,
        capability: Capability,
        depth: Depth,
    },
    /// "I appended grant/revoke records to my grants subtree — refold."
    /// Broker recomputes; affected apps get `CapabilityChanged` pushes.
    NotifyGrantsChanged { req_id: u64 },

    // ── §4.3 services (M2) ──────────────────────────────────────────────
    /// Advertise an ability this app offers (recorded in /services + live).
    PublishService { req_id: u64, decl: ServiceDecl },
    UnpublishService { req_id: u64, name: String },
    DiscoverServices {
        req_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
    },
    /// Call a service. `pvosd` authorizes (Service capability) then routes.
    CallService {
        req_id: u64,
        provider: ProviderId,
        service: String,
        method: String,
        #[serde(default)]
        args: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    /// Provider's answer to an `IncomingServiceCall`.
    ServiceReply { call_id: u64, outcome: CallOutcome },
    /// PVOS D254 — a topic belongs to its provider. No `provider` (or your
    /// own app id) is your own topics; another provider's needs a `Service`
    /// capability on that provider.
    Subscribe {
        req_id: u64,
        topic: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<ProviderId>,
    },
    Unsubscribe {
        req_id: u64,
        topic: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<ProviderId>,
    },
    /// Provider emits an event on one of its topics (fan-out via pvosd).
    EmitEvent {
        req_id: u64,
        topic: String,
        payload: Value,
    },

    // ── §4.4 UI — Mode B view-model (M3, doc 08 §4) ─────────────────────
    /// Render (or re-render) a surface. `pvosd` relays it to any desktop
    /// session with this surface open; re-push is reconciled, not reloaded.
    PushViewModel {
        req_id: u64,
        surface: String,
        /// D47: OPAQUE — pvosd routes by surface+actor and must never
        /// die on UI vocabulary it doesn't know (the D43 §0b class).
        view_model: serde_json::Value,
        /// D39: `None` broadcasts to every session with the surface open
        /// (the pre-D39 behavior); `Some(actor)` renders for ONE session —
        /// per-viewer navigation on a shared surface.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<String>,
    },
    /// Append lines to a `log` component (D2 streaming — no full re-push).
    AppendLog {
        req_id: u64,
        surface: String,
        component_id: String,
        lines: Vec<String>,
    },
    /// Runtime capability request → owner consent (the M2 deferral). `pvosd`
    /// prompts on the desktop; on approval it composes the ApprovalContext,
    /// the companion signs `user_action`, and the grant is written.
    RequestCapability {
        req_id: u64,
        capability: Capability,
        reason: String,
    },

    // ── §4.5 admin (owner sessions only; doc 04) ────────────────────────
    /// Install/register an app (consent + keygen live client-side in the
    /// CLI; by sending this, the owner has consented). The pre-D195 op: it
    /// cannot carry a `ui/`, so pvosd refuses it for an app with an iframe
    /// surface — [`ClientMsg::AdminInstallApp`] is the install.
    AdminInstall {
        req_id: u64,
        app_id: AppId,
        pubkey: String, // hex
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest: Option<String>, // manifest JSON
    },
    /// D195: the whole install, done by pvosd — register, import `ui` into
    /// `/apps/<id>/ui`, pin `integrity.ui_root` (only from that import; a
    /// pin in `manifest` is dropped), store the manifest. Answered with
    /// [`ServerMsg::AppInstalled`]. A pre-D195 pvosd skips this tag without
    /// replying, so a client looks for [`OP_INSTALL_APP`] in
    /// `AdminState.daemon_ops` before sending it.
    AdminInstallApp {
        req_id: u64,
        app_id: AppId,
        pubkey: String, // hex
        manifest: String, // manifest JSON
        /// The app's `ui/` bundle; `None` = the app dir has no `ui/`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ui: Option<Vec<UiFile>>,
        /// PVOS D204: the owner confirmed taking over an id another app holds
        /// (another publisher, or another name). Without it pvosd refuses
        /// such an install with `takeover`; an upgrade never needs it.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        take_over: bool,
    },
    AdminGrant {
        req_id: u64,
        subject: Subject,
        capability: Capability,
        depth: Depth,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expiry: Option<Timestamp>,
    },
    AdminRevoke { req_id: u64, grant_id: String },
    /// Apps + the full grant log with effectiveness — the CLI's list view.
    AdminList { req_id: u64 },
    AdminStartApp { req_id: u64, app_id: AppId },
    AdminStopApp { req_id: u64, app_id: AppId },

    // ── D18 invites (admin sessions; the DELEGATION is still signed by a
    //    member companion — the daemon witnesses, it does not vouch) ──────
    /// Mint an invite for `member` with `role`'s capability set. `pvosd`
    /// relays the delegation digest to a connected desktop for a companion
    /// `user_action` signature (or signs via the local companion in dev), so
    /// this request completes asynchronously — the CLI waits.
    AdminInviteCreate {
        req_id: u64,
        member: String,
        /// The invitee's contact email (§3'''') — required; pinned inside
        /// the signed delegation.
        #[serde(default)]
        email: String,
        role: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_ms: Option<u64>,
    },
    AdminInviteList { req_id: u64 },
    AdminInviteRevoke { req_id: u64, invite_id: String },

    // ── D18 slice 4: app sharing ─────────────────────────────────────────
    /// Share an installed app with a role (an owner-issued grant with
    /// subject `role:<name>`). Refused for admin-only apps. → `Granted`.
    AdminShare { req_id: u64, app_id: AppId, role: String },
    /// Revoke the share (the grant, by content). → `Ack`.
    AdminUnshare { req_id: u64, app_id: AppId, role: String },

    // ── D18 slice 5: membership ──────────────────────────────────────────
    /// Every member: name, role, custody, invited-by. → `MemberList`.
    AdminMemberList { req_id: u64 },
    /// The impact report BEFORE a removal (§3''' warning): live sessions,
    /// pending invites they signed, and the accounts their redeemed invites
    /// created. → `MemberImpact`.
    AdminMemberInspect { req_id: u64, member: String },
    /// Remove the membership: revokes their sessions + session keys, their
    /// pending invites, and their identity key at pvfsd; deletes the pairing
    /// record. Their data stays; NO cascade to accounts they invited. → `Ack`.
    AdminMemberRemove { req_id: u64, member: String },
    /// Set a member's contact email (M10) — always lands UNVERIFIED; the
    /// member confirms from their own desktop. Routed through the daemon so
    /// the LIVE pairing table updates immediately. → `Ack`.
    AdminMemberSetEmail { req_id: u64, member: String, email: String },
    /// Change a member's role — an explicit re-grant: the pinned capability
    /// set becomes the new role's defaults; the custody gate applies as at
    /// enrolment (admin-carrying roles refuse non-remote custody).
    AdminMemberSetRole { req_id: u64, member: String, role: String },
    /// PVOS D259: the whole set of `app_id`'s member actions `member` may
    /// take, re-signed into their pairing record. Empty clears it. → `Ack`.
    AdminMemberSetAppActions { req_id: u64, member: String, app_id: String, actions: Vec<String> },
    /// D36: mint a REKEY invite for an existing member — redemption replaces
    /// their keys (any custody path); data, role and email survive.
    AdminMemberRekey { req_id: u64, member: String },
    /// D36: archive a REMOVED member's leftover home under /members/.archive
    /// so a future same-name invite starts clean instead of reattaching.
    AdminMemberArchiveData { req_id: u64, member: String },

    // ── D67 C2: persistent sessions ──────────────────────────────────────
    /// Every remembered sign-in (M9). → `SessionList`.
    AdminSessionList { req_id: u64 },
    /// Revoke one remembered session, or ALL when `id` is None. Routed
    /// through the daemon on purpose: written offline this fails OPEN — the
    /// record says revoked while the running daemon keeps honouring the
    /// live session, i.e. a "sign out everywhere" that signs nobody out
    /// (D67 §1). Live sessions holding the token are dropped, and each
    /// session's PVFS key is retired, so the credential cannot outlive it.
    /// → `Revoked`.
    AdminSessionRevoke { req_id: u64, id: Option<String> },

    // ── D67 C2b: companion pairing ───────────────────────────────────────
    /// Pair a member's companion: the daemon runs the doc-16 handshake over
    /// `socket` and writes the pairing record. The CLI keeps the prompting
    /// (member name, server name, origins) — only the EXECUTION moves here,
    /// because a pairing record is a control record, and `pvos.yml` re-pairs
    /// with pvosd live (D67 §6.1). → `Paired`.
    AdminPair {
        req_id: u64,
        member: String,
        /// Name shown in the companion's own prompt, on the human's machine.
        server_name: String,
        /// Companion agent socket, as the CLI resolved it.
        socket: String,
        /// Web origins the desktop is served from.
        origins: Vec<String>,
    },

    // ── D67 C2c: the owner's notification inbox ──────────────────────────
    /// The owner's notifications. Routed because the DAEMON is what writes
    /// this store (apps notify through it), so an offline read misses
    /// everything since boot — the opposite staleness to the grant case, and
    /// just as misleading. → `Notifications`.
    AdminNotifyList { req_id: u64 },
    /// Dismiss one notification, or ALL when `id` is None. → `Revoked`
    /// (reusing the count reply — same shape, "how many did that touch").
    AdminNotifyDismiss { req_id: u64, id: Option<String> },

    // ── D67 C2c: outbound mail relay ─────────────────────────────────────
    /// Write the mail relay config and stash its password in the keychain,
    /// both control-tree writes. `mail test` is NOT here: it only reads and
    /// sends, so it never needed the daemon. → `Ack`.
    /// D222d: the log destinations and their health (owner).
    AdminLogList { req_id: u64 },
    /// D222d: add or replace one. `original` = the one being edited (a
    /// rename); `token`: `None` keeps the stored one, `Some("")` clears it.
    AdminLogSet {
        req_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original: Option<String>,
        dest: crate::desktop::LogDestinationEdit,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    AdminLogRemove { req_id: u64, name: String },
    /// D222d: send one test event now; `Ack` when the receiver took it.
    AdminLogTest { req_id: u64, name: String },
    AdminMailSetup {
        req_id: u64,
        host: String,
        port: u16,
        /// `starttls` | `tls` | `none` (parsed daemon-side, same as the CLI).
        security: String,
        username: String,
        /// Travels the owner-authenticated control socket, exactly as
        /// `secret put` already does.
        password: String,
        from: String,
    },
    /// PVOS D262: save the DNS setting for PVOS apps (`config`, the record's
    /// JSON), or clear it (`None`). It never touches the server's own DNS.
    /// → `Ack`.
    AdminDnsSet {
        req_id: u64,
        #[serde(default)]
        config: Option<serde_json::Value>,
    },
    /// PVOS D262: the DNS setting for apps, and the host's resolvers. →
    /// `DnsSetting`.
    AdminDnsShow { req_id: u64 },
    /// PVOS D290: the notification routing. `routing` is absent when none
    /// is saved. → `NotifyRouting`.
    AdminNotifyRoutingShow { req_id: u64 },
    /// PVOS D290: save the notification routing. The desktop's Settings op
    /// calls the same `notify_routing_set`. → `Ack`.
    AdminNotifyRoutingSet {
        req_id: u64,
        routing: serde_json::Value,
    },
    /// PVOS D290: a mounts, forest, instance, or replica operation. `action`
    /// is `show`, `bind`, `unbind`, `scan`, `serve`, `stop`, `boot`,
    /// `register`, `unregister`, `instance-add`, `instance-remove`, or
    /// `replica`. The same functions as Settings → Mounts. → `MountsReport`.
    AdminMounts {
        req_id: u64,
        action: String,
        #[serde(default)]
        args: serde_json::Value,
    },
    /// PVOS D290: mint a scoped token. The reply waits on the companion.
    /// The secret is in `TokenCreated` once, and stored only as a hash.
    AdminTokenCreate {
        req_id: u64,
        #[serde(default)]
        label: String,
        operations: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        app: Option<String>,
        ttl_ms: u64,
    },
    /// PVOS D290: the tokens, without secrets. → `TokenList`.
    AdminTokenList { req_id: u64 },
    /// PVOS D290: end a token. It fails its next call. → `Ack`.
    AdminTokenRevoke { req_id: u64, token_id: String },
    /// PVOS D290: API methods apps have declared. → `AppMethods`.
    AdminAppMethods { req_id: u64 },
    /// PVOS D290: call one declared API method. A method that is only
    /// published, including a scheduler callback, is refused. → `CallResult`.
    AdminAppCall {
        req_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        service: String,
        method: String,
        #[serde(default)]
        args: serde_json::Value,
    },
}

impl ClientMsg {
    /// The message's wire name (its serde `type`) — what a log line calls
    /// it (PVOS D222b), without serializing the whole message.
    pub fn op_name(&self) -> &'static str {
        match self {
            ClientMsg::Auth { .. } => "auth",
            ClientMsg::GetContext { .. } => "get_context",
            ClientMsg::ListCapabilities { .. } => "list_capabilities",
            ClientMsg::ValidateDelegation { .. } => "validate_delegation",
            ClientMsg::NotifyGrantsChanged { .. } => "notify_grants_changed",
            ClientMsg::PublishService { .. } => "publish_service",
            ClientMsg::UnpublishService { .. } => "unpublish_service",
            ClientMsg::DiscoverServices { .. } => "discover_services",
            ClientMsg::CallService { .. } => "call_service",
            ClientMsg::ServiceReply { .. } => "service_reply",
            ClientMsg::Subscribe { .. } => "subscribe",
            ClientMsg::Unsubscribe { .. } => "unsubscribe",
            ClientMsg::EmitEvent { .. } => "emit_event",
            ClientMsg::PushViewModel { .. } => "push_view_model",
            ClientMsg::AppendLog { .. } => "append_log",
            ClientMsg::RequestCapability { .. } => "request_capability",
            ClientMsg::AdminInstall { .. } => "admin_install",
            ClientMsg::AdminInstallApp { .. } => "admin_install_app",
            ClientMsg::AdminGrant { .. } => "admin_grant",
            ClientMsg::AdminRevoke { .. } => "admin_revoke",
            ClientMsg::AdminList { .. } => "admin_list",
            ClientMsg::AdminStartApp { .. } => "admin_start_app",
            ClientMsg::AdminStopApp { .. } => "admin_stop_app",
            ClientMsg::AdminInviteCreate { .. } => "admin_invite_create",
            ClientMsg::AdminInviteList { .. } => "admin_invite_list",
            ClientMsg::AdminInviteRevoke { .. } => "admin_invite_revoke",
            ClientMsg::AdminShare { .. } => "admin_share",
            ClientMsg::AdminUnshare { .. } => "admin_unshare",
            ClientMsg::AdminMemberList { .. } => "admin_member_list",
            ClientMsg::AdminMemberInspect { .. } => "admin_member_inspect",
            ClientMsg::AdminMemberRemove { .. } => "admin_member_remove",
            ClientMsg::AdminMemberSetEmail { .. } => "admin_member_set_email",
            ClientMsg::AdminMemberSetRole { .. } => "admin_member_set_role",
            ClientMsg::AdminMemberSetAppActions { .. } => "admin_member_set_app_actions",
            ClientMsg::AdminMemberRekey { .. } => "admin_member_rekey",
            ClientMsg::AdminMemberArchiveData { .. } => "admin_member_archive_data",
            ClientMsg::AdminSessionList { .. } => "admin_session_list",
            ClientMsg::AdminSessionRevoke { .. } => "admin_session_revoke",
            ClientMsg::AdminPair { .. } => "admin_pair",
            ClientMsg::AdminNotifyList { .. } => "admin_notify_list",
            ClientMsg::AdminNotifyDismiss { .. } => "admin_notify_dismiss",
            ClientMsg::AdminLogList { .. } => "admin_log_list",
            ClientMsg::AdminLogSet { .. } => "admin_log_set",
            ClientMsg::AdminLogRemove { .. } => "admin_log_remove",
            ClientMsg::AdminLogTest { .. } => "admin_log_test",
            ClientMsg::AdminMailSetup { .. } => "admin_mail_setup",
            ClientMsg::AdminDnsSet { .. } => "admin_dns_set",
            ClientMsg::AdminDnsShow { .. } => "admin_dns_show",
            ClientMsg::AdminNotifyRoutingShow { .. } => "admin_notify_routing_show",
            ClientMsg::AdminNotifyRoutingSet { .. } => "admin_notify_routing_set",
            ClientMsg::AdminMounts { .. } => "admin_mounts",
            ClientMsg::AdminTokenCreate { .. } => "admin_token_create",
            ClientMsg::AdminTokenList { .. } => "admin_token_list",
            ClientMsg::AdminTokenRevoke { .. } => "admin_token_revoke",
            ClientMsg::AdminAppMethods { .. } => "admin_app_methods",
            ClientMsg::AdminAppCall { .. } => "admin_app_call",
        }
    }
}

/// `pvosd` → app. Internally tagged on `"type"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// First message on connect.
    Challenge {
        nonce: String, // hex
        instance_id: String,
        expiry_ms: u64,
    },
    /// Handshake success — the attach-time context.
    Ready { context: Context },
    /// Response to `GetContext`.
    Context { req_id: u64, context: Context },
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req_id: Option<u64>,
        code: String,
        message: String,
    },

    // ── M2 responses ────────────────────────────────────────────────────
    /// Generic success for requests with no payload (unpublish, subscribe,
    /// emit, validate-delegation, notify).
    Ack { req_id: u64 },
    /// D222d: the reply to `AdminLogList`.
    LogDestinations {
        req_id: u64,
        view: crate::desktop::LoggingView,
    },
    Capabilities {
        req_id: u64,
        capabilities: Vec<Capability>,
    },
    Services {
        req_id: u64,
        services: Vec<ServiceInfo>,
    },
    CallResult { req_id: u64, outcome: CallOutcome },

    // ── M2 pushes (no req_id — server-initiated) ────────────────────────
    /// A routed call for this provider; reply with `ServiceReply{call_id}`.
    IncomingServiceCall {
        call_id: u64,
        from: AppId,
        service: String,
        method: String,
        args: Value,
    },
    /// An event on a subscribed topic (ephemeral, at-most-once — D5).
    /// PVOS D254: `provider` is who sent it (always set by a pvosd from D254
    /// on).
    ServiceEvent {
        topic: String,
        payload: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<ProviderId>,
    },
    /// The broker recomputed effectiveness and this app's set changed.
    CapabilityChanged {
        change: CapChange,
        capability: Capability,
    },

    // ── §4.4 UI pushes to the app (M3) ──────────────────────────────────
    /// A user interacted with one of the app's rendered surfaces. `actor`
    /// (D31) is the opaque handle for the MEMBER behind the interaction —
    /// echo it in service-call args to act on their behalf; `pvosd` resolves
    /// it, apps never learn more than the handle.
    UiEvent {
        surface: String,
        action: String,
        #[serde(default)]
        payload: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<String>,
    },
    /// A window's lifecycle changed (open/close/focus — doc 08 §2).
    /// (`RequestCapability` resolves via the shared `Granted` reply below, or
    /// an `Error{code}` of `denied` | `parked`.)
    UiLifecycle {
        surface: String,
        phase: UiPhase,
        /// D39: whose window this is — the same opaque handle UiEvent
        /// carries, so an app can render a per-viewer view on Open.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<String>,
    },
    /// D45: pvosd suggests this backgrounded app park itself (exit cleanly;
    /// supervision respawns it on next demand). The SDK consults the app's
    /// `on_park` handler; declining is legitimate while work is in flight.
    /// An SDK that predates it skips the unknown tag (D47/D50).
    ParkHint,

    // ── admin responses ─────────────────────────────────────────────────
    Granted { req_id: u64, grant_id: String },
    AdminState {
        req_id: u64,
        apps: Vec<AdminAppInfo>,
        records: Vec<AdminGrantInfo>,
        /// D195: the admin ops this pvosd has beyond the original set (e.g.
        /// [`OP_INSTALL_APP`]). Empty from a pre-D195 pvosd — which answers
        /// this list but silently skips an op it does not know, so a client
        /// asks here before sending one.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        daemon_ops: Vec<String>,
    },
    /// D195: the answer to [`ClientMsg::AdminInstallApp`].
    AppInstalled {
        req_id: u64,
        app_id: AppId,
        pubkey_hex: String,
        region: NodeId,
        /// The pinned `integrity.ui_root`; `None` when no `ui/` was sent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ui_root: Option<String>,
        /// The live pvfsd's wire protocol, for the D63 install warning.
        pvfs_proto: u32,
    },

    // ── D18 invite responses ────────────────────────────────────────────
    /// The one and only time the CODE crosses a wire in clear. `emailed`
    /// says PVOS delivered it to the invitee's address itself — in which
    /// case redemption PROVES mailbox custody and the email arrives
    /// verified; otherwise the inviter hands the code out of band and the
    /// address stays a claim.
    InviteCreated {
        /// D36: minting for a name whose REMOVED predecessor left data —
        /// redeeming will REATTACH it (archive first for a clean start).
        #[serde(default)]
        reattach_warning: bool,
        req_id: u64,
        invite_id: String,
        code: String,
        expires_ms: u64,
        #[serde(default)]
        emailed: bool,
    },
    InviteList {
        req_id: u64,
        invites: Vec<InviteInfo>,
    },

    // ── D18 slice 5 responses ────────────────────────────────────────────
    MemberList {
        req_id: u64,
        members: Vec<MemberInfo>,
    },
    /// D67 C2: remembered sign-ins.
    SessionList {
        req_id: u64,
        sessions: Vec<SessionInfo>,
    },
    /// D67 C2: how many sessions the revoke actually killed.
    Revoked {
        req_id: u64,
        count: u64,
    },
    /// D67 C2c: the owner's inbox, newest first.
    Notifications {
        req_id: u64,
        items: Vec<crate::notify::Notification>,
    },
    /// D67 C2b: the pairing that was written.
    Paired {
        req_id: u64,
        member: String,
        role: String,
        identity_pubkey_hex: String,
    },
    /// What removing a member would touch (§3''' warning): the admin reads
    /// this BEFORE confirming. `invited_members` are accounts the member's
    /// redeemed invites created — listed for a human decision, never
    /// auto-cascaded.
    MemberImpact {
        req_id: u64,
        member: String,
        sessions: usize,
        pending_invites: Vec<InviteInfo>,
        invited_members: Vec<String>,
    },
    /// PVOS D262: the DNS setting for apps (`None`: the host resolves for
    /// them), the host's own resolvers beside it, and the notice to show.
    DnsSetting {
        req_id: u64,
        #[serde(default)]
        config: Option<serde_json::Value>,
        host_resolvers: Vec<String>,
        notice: String,
    },
    /// PVOS D290: the notification routing. `routing` is absent when none
    /// is saved.
    NotifyRouting {
        req_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        routing: Option<serde_json::Value>,
    },
    /// PVOS D290: a mounts listing (`view`) or the sentence a change produced.
    MountsReport {
        req_id: u64,
        summary: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        view: Option<crate::desktop::MountsView>,
    },
    /// PVOS D290: a scoped token, just minted. `secret` is shown once.
    TokenCreated {
        req_id: u64,
        token_id: String,
        secret: String,
        expires_ms: u64,
    },
    /// PVOS D290: the scoped tokens. No secret, no hash.
    TokenList {
        req_id: u64,
        tokens: Vec<ApiTokenInfo>,
    },
    /// PVOS D290: declared API methods. No secrets.
    AppMethods {
        req_id: u64,
        methods: Vec<ApiMethodInfo>,
    },
}

/// One declared API method, as `pvos apps` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiMethodInfo {
    pub id: String,
    pub provider: String,
    pub service: String,
    pub method: String,
    #[serde(default)]
    pub companion: bool,
}

/// A scoped token as listed. The secret is not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTokenInfo {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    pub expires_ms: u64,
    pub created_by: String,
}

/// A membership as listed (D18 slice 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub member: String,
    pub role: String,
    /// remote | browser | server-hosted (legacy) — §3''' custody tier.
    pub custody: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited_by: Option<String>,
    pub paired_at_ms: u64,
    /// Contact email (§3'''') and whether delivery has CONFIRMED it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    /// PVOS D259: app id → the actions this member may take there.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub app_actions: std::collections::BTreeMap<String, Vec<String>>,
}

/// A remembered sign-in as listed (D67 C2) — display data only. Deliberately
/// NOT the `SessionRecord`: that carries `token_hash`, and a bearer
/// credential's hash has no business on a wire it is not needed on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub member: String,
    /// The browser's user-agent, so a list is recognisable rather than ids.
    #[serde(default)]
    pub label: String,
    pub last_seen_ms: u64,
    pub expires_ms: u64,
}

/// An invite as listed (D18) — display data only, never the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteInfo {
    pub invite_id: String,
    pub member: String,
    /// D36: "join" (default) or "rekey" — an operator deciding whether to
    /// revoke should know which kind of pending code is out there.
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub email: String,
    pub role: String,
    /// pending | redeemed | revoked (+ "expired" is a pending past its time,
    /// computed by the viewer from `expires_ms`).
    pub state: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub inviter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeemed_ms: Option<u64>,
}

/// D195: the `AdminState.daemon_ops` entry for [`ClientMsg::AdminInstallApp`]
/// (its wire tag).
pub const OP_INSTALL_APP: &str = "admin_install_app";

/// D195: the most `ui/` bytes one [`ClientMsg::AdminInstallApp`] carries.
/// Base64 inflates them by a third, so the frame stays under
/// [`crate::frame::MAX_FRAME`] (16 MiB) with room for the manifest.
pub const MAX_UI_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

/// D195: one file of an app's `ui/` bundle. `path` is relative to `ui/`,
/// `/`-separated; `bytes` travel as base64 in the JSON frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiFile {
    pub path: String,
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
}

mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        B64.decode(text).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAppInfo {
    pub app_id: AppId,
    pub pubkey_hex: String,
    pub region: NodeId,
    /// The app's UI surfaces (M3.5) so the desktop knows Mode A (iframe) vs
    /// Mode B (view-model) per surface. Empty for apps with no declared UI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<crate::manifest::UiSurface>,
    /// The manifest's human name — what the desktop labels the icon (M4a;
    /// app ids like reverse-domain strings are not labels).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Does this app have a live supervised backend right now? The shell shows
    /// it on the icon and only offers "force quit" for something that is
    /// actually running.
    #[serde(default)]
    pub running: bool,
    /// PVOS D209: where the desktop fetches the app's icon
    /// (`/apps/<id>/icon`) — set when the manifest declares `icon`. The
    /// route checks the file; a page that cannot load it draws initials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminGrantInfo {
    pub record: GrantRecord,
    /// For grant records: currently effective? (revokes: always false.)
    pub effective: bool,
    /// `"system"` or `"app:<id>"` — which log it was read from.
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapChange {
    Granted,
    Revoked,
}

/// A UI surface's window lifecycle phase (doc 08 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiPhase {
    Open,
    Close,
    Focus,
}
