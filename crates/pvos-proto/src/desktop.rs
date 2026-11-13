//! Desktop ↔ `pvosd` websocket protocol (doc 08 §1). The browser can't open
//! the Unix control socket, so the desktop speaks these JSON frames over a
//! websocket; `pvosd` bridges them to the app control plane.
//!
//! Auth is companion-brokered "Sign in with PVFS" (doc 08 §1.1, doc 16 §6):
//! login → challenge → companion signs → session token. Every subsequent frame
//! carries the token; there is no anonymous desktop access.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AdminAppInfo, AdminGrantInfo, Capability, UiPhase};

/// Desktop → `pvosd`. Login is unauthenticated; everything else rides
/// [`DesktopMsg::Authed`] carrying the session token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DesktopToServer {
    /// Begin sign-in: `pvosd` replies `LoginChallenge`.
    Login,
    /// The companion's signature over the challenge (hex) + the identity key
    /// it signed with (hex). `pvosd` verifies the key is an authorized member.
    LoginAnswer { pubkey: String, sig: String },
    /// The companion's answer to a `RelayRequest`, forwarded verbatim by the
    /// page (M3.1). Accepted pre-auth ONLY for this connection's own login
    /// relay; consent relays require the session that received the request.
    RelayReply { relay_id: u64, result: RelayOutcome },
    /// An authenticated action carrying the session token.
    Authed { token: String, action: DesktopAction },
    /// Redeem an invite (D18) — unauthenticated like `Login`: the invitee has
    /// no session yet; the CODE is the credential. `pvosd` replies
    /// `RedeemChallenge` (or a generic `Error` that does not say why).
    RedeemInvite { code: String },
    /// The invitee companion's half of the chain: its identity pubkey (hex)
    /// and its signature (hex) over the acceptance digest
    /// `{invite_id, pubkey, code}`. `pvosd` verifies the full chain, burns
    /// the code, and pairs the member.
    RedeemAnswer { invite_id: String, pubkey: String, sig: String },
    /// D193: redeem with a PASSKEY and a personal forest. The page made the
    /// person's phrase and keys, wrapped the seed under a passkey (`blob`:
    /// ciphertext the server stores but cannot open), signed the acceptance
    /// with the identity key, and signed the genesis of their personal
    /// forest — built from parameters IT chose and the challenge's
    /// `personal_host`. Refused for admin-carrying invites (browser custody).
    RedeemPersonal {
        invite_id: String,
        /// The identity key (`3'/0'`, hex): the member's identity, and the
        /// personal forest's owner device.
        identity: String,
        /// The root key (`0'`, hex): roots the personal forest.
        root: String,
        /// The device key (`1'/0'`, hex): the personal forest's owner device
        /// — it signs the binding and the session certificates.
        owner: String,
        /// The identity's signature over the acceptance digest (hex).
        sig: String,
        genesis: PersonalGenesis,
        blob: String,
        /// The owner key's signature over pvos-core
        /// `personal_binding_digest(rp_id, member, forest_id, root_node_id)`
        /// — rp_id the page's hostname: what later sign-ins check before
        /// signing a session certificate.
        binding_sig: String,
    },
    /// D33: fetch a browser member's wrapped-key blob to begin passkey
    /// sign-in. Pre-auth by necessity (the blob IS how they sign in);
    /// rate-limited, one generic refusal for unknown/non-browser members.
    BrowserBlobGet { member: String },
    /// D33 (2026-07-29): the same lookup keyed by the WEBAUTHN CREDENTIAL ID
    /// the tap just proved — so sign-in never asks for a member name, even
    /// for v1 blobs whose user handle carries none. Credential ids are high
    /// entropy (unguessable), so this is a strictly narrower surface than
    /// the by-name lookup; same rate limit, same generic refusal.
    BrowserBlobByCred { cred: String },
    /// D33: begin browser sign-in — replies `LoginChallenge` (the same v2
    /// digest binding a fresh session key); the page answers with the
    /// standard `LoginAnswer`, verified against the pairing table.
    LoginBrowser { member: String },
    /// D193: the page's answer to `SessionCertRequest` — the session
    /// certificate it built and its owner key signed (pvfs-core
    /// `session_cert_events`: the session key a member of the personal
    /// forest, `rw` on its root until `expires_at`), in log order.
    SessionCert { at: u64, expires_at: u64, sigs: Vec<String> },
    /// D193: the answer to `BindChallenge` — the session's browser key's
    /// signature (P-256, raw r‖s, hex) over `pvos:session-bind:v1:` and the
    /// nonce.
    BindProof { sig: String },
    /// D212: renew this connection's session grant in the person's own
    /// forest before it ends (only inside its renewal window,
    /// `SessionGrant::renew_from_ms`). pvosd answers with the `session_cert`
    /// relay (a companion member) or a `SessionCertRequest` (a passkey
    /// member, whose page has just unlocked the key with a tap), then a
    /// fresh `SessionGrant`; a refusal is `Error { code: "renew" }`.
    RenewGrant { token: String },
}

/// What came back from the companion's `/relay` (M3.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RelayOutcome {
    /// `{sig, pubkey}` from the webagent — the identity key + its signature
    /// over the relayed digest.
    Signed { pubkey: String, sig: String },
    /// The webagent's typed error (`locked`, `denied`, `bad_origin`,
    /// `unpaired`, …) so `pvosd` can park/deny precisely.
    Failed { code: String, message: String },
    /// D193: a session certificate the companion built (owner key, the times
    /// it chose, a signature per event in log order).
    Certified { pubkey: String, at: u64, expires_at: u64, sigs: Vec<String> },
    /// D193: a personal forest's genesis the companion built and signed.
    Genesis(Box<GenesisOutcome>),
    /// D193: a confirmed delete or grant — the owner key over pvos-core
    /// `confirm_digest`.
    Confirmed { pubkey: String, sig: String },
}

/// D193: a personal forest's genesis as a companion returns it: the person's
/// keys, the parameters it chose, five signatures in log order, and the owner
/// key's binding for the asking site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisOutcome {
    pub root: String,
    pub owner: String,
    pub identity: String,
    pub forest_id: String,
    pub instance_id: String,
    pub created_at: u64,
    pub root_nonce: String,
    pub sigs: Vec<String>,
    pub binding_sig: String,
}

/// The authenticated desktop actions (owner authority).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DesktopAction {
    /// Installed apps + the grant log (the launcher + admin view).
    List,
    Launch { app_id: String },
    StopApp { app_id: String },
    /// Open/close/focus a surface window (maps to `UiLifecycle` for the app).
    Surface { app_id: String, surface: String, phase: UiPhase },
    /// A user interaction on a rendered surface → relayed to the app.
    UiEvent {
        app_id: String,
        surface: String,
        ui_action: String,
        #[serde(default)]
        payload: Value,
    },
    /// Answer a pending consent prompt.
    ConsentReply { consent_id: u64, approve: bool },
    /// The owner's notification list (M6). Replies `Notifications`.
    NotificationList,
    /// Mark read / dismiss — one by id, or all when `id` is absent.
    NotificationUpdate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// `true` dismisses, `false` marks read.
        #[serde(default)]
        dismiss: bool,
    },
    /// Fetch the owner's saved desktop preferences (icon positions, layout,
    /// visual settings) — an opaque JSON blob pvosd stores per owner so
    /// customizations follow across devices. Replies `Prefs`.
    GetPrefs,
    /// Persist the desktop preferences blob (opaque to pvosd).
    SetPrefs { json: String },
    /// D193: bind this session to the page's browser key (P-256 raw public
    /// point, hex) — once, right after sign-in. A cookie then restores the
    /// session only on a connection that proves the key (`BindChallenge`).
    BindSession { key: String },
    /// D193: add a passkey made on this device — after a recovery by phrase —
    /// wrapping the same seed (a v3 blob; ciphertext the server cannot open).
    AddPasskey { blob: String },
    /// D30: one Settings operation (shell Settings window). Every op maps
    /// 1:1 onto the same plane methods the CLI admin channel uses, behind
    /// the same capability asks — the GUI is a veneer, never a second path.
    Settings { op: SettingsOp },
    /// D280: the Share window. The same `pvos.share` service the CLI uses.
    /// Putting a file into a folder is `POST /share-upload`, because a
    /// websocket frame cannot carry the bytes.
    Share { op: ShareOp },
    /// M10: mail me a verification code for my (unverified) email.
    EmailVerifySend,
    /// M10: the code from that mail — on a match, the membership's email
    /// flips to VERIFIED.
    EmailVerifyConfirm { code: String },
    /// A Mode A iframe's mediated bridge op (M3.5, doc 08 §3). The DESKTOP
    /// asserts `app_id` (from the window it created — the iframe can't forge
    /// it); `pvosd` runs the op scoped to that app. `req_id` correlates a
    /// `BridgeReply` back through the desktop to the iframe.
    BridgeCall {
        req_id: u64,
        app_id: String,
        surface: String,
        op: BridgeOp,
    },
}

/// D280 Share window operations. Creating a link still waits on the
/// companion. Uploading bytes is `POST /share-upload`, not one of these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ShareOp {
    List,
    /// Children of `path` (empty is the top of the forest).
    Browse { path: String },
    /// A folder link's current files, so the owner can add more.
    Open { id: String },
    Create {
        name: String,
        /// A file or folder already in the forest.
        node: String,
        /// Blank means no time limit. Otherwise a number of days.
        #[serde(default)]
        days: String,
        #[serde(default)]
        password: String,
    },
    Stop { id: String },
}

/// What the Share window draws. `entries` are the folder being browsed, or
/// the folder link that is open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShareDesktopState {
    pub links: Vec<crate::ShareSummary>,
    pub forest: String,
    pub path: String,
    /// The folder `path` names. Empty at the top of the forest.
    #[serde(default)]
    pub here: String,
    pub entries: Vec<ShareBrowseEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShareBrowseEntry {
    pub id: String,
    pub name: String,
    pub label: String,
    pub size: u64,
    pub folder: bool,
}

/// D30 Settings operations. Mutations answer with a fresh [`SettingsState`]
/// push (server-recomputed — the page never assembles authority) plus a
/// toast; failures answer the usual typed `Error`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SettingsOp {
    /// The whole state this SESSION may see.
    Get,
    /// The §3''' removal impact report — the confirm dialog's content.
    MemberInspect { member: String },
    MemberRemove { member: String },
    MemberSetEmail { member: String, email: String },
    /// Change a member's role (member/admin) — same re-grant semantics and
    /// custody gate as the CLI path.
    MemberSetRole { member: String, role: String },
    /// PVOS D259: set the actions `member` may take in `app_id` (the whole
    /// set for that app; empty clears it). Same gate as a role change.
    MemberSetAppActions { member: String, app_id: String, actions: Vec<String> },
    /// D36: mint a rekey invite (completes like InviteCreate, via the relay).
    MemberRekey { member: String },
    /// Mint an invite: the companion still signs the delegation via the
    /// normal relay prompt; completion arrives as `InviteMinted`.
    InviteCreate { member: String, email: String, role: String },
    InviteRevoke { invite_id: String },
    SessionRevoke { id: String },
    Share { app_id: String, role: String },
    Unshare { app_id: String, role: String },
    /// Relay settings. `password: None` keeps the stored one; `Some` writes
    /// the keychain (write-only — no op ever reads it back out).
    MailSet {
        host: String,
        port: u16,
        security: String,
        username: String,
        from: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    MailTest { to: String },
    // ---- PVOS D262: DNS for PVOS apps (owner-only) ------------------------
    /// Save the setting (the record's JSON: `split`, `default`). The
    /// companion confirms it first; it never touches the server's own DNS.
    DnsSet { config: serde_json::Value },
    /// Remove it: apps use the host's resolver again.
    DnsClear,
    /// The Look-up box: answered in `SettingsState.dns_answer`.
    DnsLookup { name: String },
    // ---- PVOS D264: notification settings (manage_apps) --------------------
    /// Save the routing: `{destinations, routes}`; pvosd stamps the version.
    NotifyRoutingSet { routing: serde_json::Value },
    // ---- D222d: log destinations (owner-only) ---------------------------
    /// Add or replace a destination. `original` names the one being edited
    /// (a rename); `token: None` keeps the stored token, `Some("")` clears
    /// it, anything else writes the keychain (write-only, as mail's password).
    LogSet {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original: Option<String>,
        dest: LogDestinationEdit,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    LogRemove { name: String },
    /// Send one test event to a destination now.
    LogTest { name: String },
    /// PVOS D315: the live log level. `default` goes back to the configured
    /// level now; anything else lasts `minutes` (1 to 1440).
    LogLevelSet { level: String, minutes: u32 },
    // ---- D64: PVFS mounts (owner-only; every op rides the pvfs CLI) ------
    /// Enroll a space (doc 21): bind `folder` — a tree path under the
    /// forest root, missing folders created on the way — to host directory
    /// `dir`. `kind` is in-place | migrate | mirror; `store` is required
    /// for migrate/mirror (the CLI would prompt, and pvosd never prompts).
    MountBind {
        mount: String,
        folder: String,
        dir: String,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        store: Option<String>,
        recursive: bool,
        auto_index: bool,
        #[serde(default)]
        extensions: String,
        hash_policy: String,
    },
    /// End an enrollment. Keyed by folder id, not path — stale-click safe.
    MountUnbind { mount: String, folder_id: String },
    /// Scan one enrollment (or all of them) against its directory.
    MountScan {
        mount: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder_id: Option<String>,
    },
    // ---- D70: serving a forest (owner-only; doc 00 §2.5) ----------------
    /// Start serving `mount` — pvosd spawns `pvfsd --mount` AS ITS CHILD and
    /// supervises it. Returns as soon as the child exists: the forest sits in
    /// `starting` until its socket answers, because a first replay runs
    /// minutes on a grown library.
    ForestServe { mount: String },
    /// Stop a daemon PVOS started (SIGTERM, then SIGKILL). Never touches one
    /// PVOS did not start — including the system forest's own service.
    ForestStop { mount: String },
    /// Serve this forest again whenever pvosd starts (or stop doing so).
    ForestServeAtBoot { mount: String, on: bool },
    /// Add a forest to this HOST's registry (`/etc/pvfs/forests.d`) so other
    /// tools can find it by alias. Inventory only — it neither starts nor
    /// stops anything.
    ForestRegister {
        mount: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alias: Option<String>,
    },
    /// Drop a forest from the host registry. Never touches `.pvfs/` — the
    /// forest and every byte in it stay exactly where they are.
    ForestUnregister { name: String },
    /// Remember a remote instance: addr + transport pin. Adding the entry
    /// IS the trust decision (pin-only verification, pvfs doc 17 §4).
    InstanceAdd {
        name: String,
        addr: String,
        pin: String,
    },
    InstanceRemove { name: String },
    /// Build a local replica of a remote forest — async: the initial log
    /// fetch can be long, so the op answers "started" and completion
    /// arrives as a fresh Settings push plus a notification.
    ReplicaAdd {
        dest: String,
        instance: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,
    },
}

/// Everything the Settings window may show THIS session (D30). Absent
/// sections were refused by capability, not empty.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SettingsState {
    pub can_members: bool,
    pub can_sharing: bool,
    pub can_sessions: bool,
    pub can_mail: bool,
    #[serde(default)]
    pub members: Vec<crate::MemberInfo>,
    #[serde(default)]
    pub invites: Vec<crate::InviteInfo>,
    #[serde(default)]
    pub sessions: Vec<SessionView>,
    #[serde(default)]
    pub shares: Vec<ShareView>,
    #[serde(default)]
    pub apps: Vec<AppShareView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailView>,
    /// Set only in the reply to `MemberInspect` — the confirm dialog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<ImpactView>,
    /// D64: the PVFS mounts panel (owner-only, like sessions/mail).
    #[serde(default)]
    pub can_mounts: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts: Option<MountsView>,
    /// D222d: the log destinations (owner-only).
    #[serde(default)]
    pub can_logging: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingView>,
    /// PVOS D262: DNS for PVOS apps (owner-only).
    #[serde(default)]
    pub can_dns: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsView>,
    /// Set only in the reply to `DnsLookup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_answer: Option<serde_json::Value>,
    /// PVOS D264: notification settings (`manage_apps`).
    #[serde(default)]
    pub can_notify: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<NotifyView>,
}

/// PVOS D264: the notification routing as shown, and whether the app that
/// delivers it (Monitoring, to errwatch) has applied this version.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct NotifyView {
    #[serde(default)]
    pub routing: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<RoutingApplied>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RoutingApplied {
    pub version: u64,
    pub at_ms: u64,
    pub by: String,
}

/// PVOS D262: the DNS setting for apps as shown (`None`: the host resolves
/// for them), the host's own resolvers beside it, and the notice.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DnsView {
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub host_resolvers: Vec<String>,
    #[serde(default)]
    pub notice: String,
}

/// D222d: one log destination as the form edits it. Strings throughout (an
/// empty one = not set), so the form needs no knowledge of the schema
/// beyond its fields; pvosd checks it (`pvfs_log::ship::Destination`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LogDestinationEdit {
    pub name: String,
    /// `loki`, `splunk_hec`, `syslog`, `https_json`
    pub kind: String,
    pub enabled: bool,
    /// The URL (Loki, HEC, HTTPS JSON) or `host:port` (syslog).
    pub target: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub index: String,
    pub privacy: String,
    pub min_severity: String,
    /// Empty = all.
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub tls_ca_file: String,
    #[serde(default)]
    pub tls_pin_sha256: String,
    /// PVOS D228 (D224): a Loki destination's own stream labels,
    /// `name=value, …` (empty = none).
    #[serde(default)]
    pub labels: String,
    /// PVOS D228: Elasticsearch only — the record's id as `_id`, so a resend
    /// is not stored twice (off by default; not for LogsDB `logs-*-*`).
    #[serde(default)]
    pub doc_ids: bool,
}

/// D222d: a destination as SHOWN — its settings, whether a token is stored
/// (never the token), and its health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogDestinationView {
    pub dest: LogDestinationEdit,
    pub has_token: bool,
    pub sent: u64,
    pub queued_bytes: u64,
    pub dropped: u64,
    pub last_ok_ms: u64,
    #[serde(default)]
    pub last_error: String,
    pub failing: bool,
}

/// PVOS D315: the level pvosd is logging at. `until_ms` is set only while a
/// live override has not run out.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LogLevelView {
    pub configured: String,
    pub current: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LoggingView {
    pub destinations: Vec<LogDestinationView>,
    #[serde(default)]
    pub log_level: LogLevelView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    pub id: String,
    pub member: String,
    pub label: String,
    pub last_seen_ms: u64,
    pub expires_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareView {
    pub app_id: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppShareView {
    pub app_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub admin_only: bool,
    /// PVOS D259: the actions a member may be granted in this app.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_actions: Vec<crate::manifest::MemberAction>,
}

/// The mail config as SHOWN — the password is write-only and never here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailView {
    pub host: String,
    pub port: u16,
    pub security: String,
    pub username: String,
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactView {
    pub member: String,
    pub sessions: usize,
    #[serde(default)]
    pub pending_invites: Vec<crate::InviteInfo>,
    #[serde(default)]
    pub invited_members: Vec<String>,
}

/// D64: the PVFS mounts panel state — the host's registered forests (plus
/// the system forest, registered or not) and the remembered remote
/// instances. Everything here is a read model computed server-side; kind
/// is the placement join done by pvfs itself, never re-derived in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MountsView {
    #[serde(default)]
    pub forests: Vec<ForestView>,
    #[serde(default)]
    pub instances: Vec<InstanceView>,
    /// The honest slot for a registry that couldn't be read at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForestView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub mount: String,
    /// Shortened forest id — display identity, not an addressing key.
    pub forest_id: String,
    /// The forest pvosd itself runs on.
    pub is_system: bool,
    pub registered: bool,
    pub enabled: bool,
    pub is_replica: bool,
    /// The replica's recorded source ("tcp host:port" / "socket /path").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_source: Option<String>,
    /// A pvfsd for this forest answered on its per-forest socket — whoever
    /// started it. `serve_state` says whether that daemon is one of ours.
    pub served: bool,
    /// D70: what PVOS's own supervision is doing — "starting" | "served" |
    /// "failed". `None` means PVOS is not supervising this forest at all, so
    /// `served: true` with no `serve_state` is somebody else's daemon (an
    /// operator's shell, or the system forest's systemd unit) and PVOS will
    /// not offer to stop it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_state: Option<String>,
    /// Seconds in that state — a slow first replay needs to look busy rather
    /// than hung.
    #[serde(default)]
    pub serve_secs: u64,
    /// The child's own last words, kept until the next successful serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_error: Option<String>,
    /// D70 C1: bring this forest up when pvosd starts. Recorded in PVOS's
    /// own control tree — a supervised forest dies with pvosd (doc 00 §2.5),
    /// so without a record a restart silently forgets it.
    #[serde(default)]
    pub serve_at_boot: bool,
    #[serde(default)]
    pub bindings: Vec<BindingView>,
    /// Why bindings couldn't be read ("not served — bindings unavailable").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One space enrollment (doc 21), kind already joined from placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingView {
    pub folder_id: String,
    /// Tree path from the forest root; absent when the folder is detached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_path: Option<String>,
    /// The bound host directory (plain path, not the file:// uri).
    pub source: String,
    /// in-place | migrate | mirror.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    pub recursive: bool,
    pub auto_index: bool,
    /// Comma list; empty = all.
    #[serde(default)]
    pub extensions: String,
    pub hash_policy: String,
    pub bound_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceView {
    pub name: String,
    pub addr: String,
    /// A pin PREFIX wide enough to compare against a printed pin — the
    /// full pin only ever travels inward (InstanceAdd), never back out.
    pub pin_prefix: String,
}

/// The small, mediated set of iframe→desktop operations (doc 08 §3). Anything
/// richer goes through the app's own backend + Channel 2, not the bridge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BridgeOp {
    /// A desktop toast.
    Notify { level: String, text: String },
    /// Request a capability at runtime → the owner-consent flow for this app.
    RequestCapability { capability: Capability, reason: String },
    /// The services this app may see.
    DiscoverServices {
        #[serde(default)]
        query: Option<String>,
    },
    /// Launch another installed app (owner-role-gated).
    OpenApp { app_id: String },
}

/// `pvosd` → desktop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToDesktop {
    /// The 32-byte digest (hex) to hand to the companion's `/sign-in` (doc 16
    /// §6). The browser forwards it verbatim — it never reconstructs the
    /// `auth_digest`; `pvosd` composed it and remembers it for verification.
    /// D193: and its fields, from which a passkey page builds the digest
    /// itself rather than sign one it was handed (pvos-core `login_digest`).
    LoginChallenge {
        digest: String,
        #[serde(default)]
        nonce: String,
        #[serde(default)]
        instance_id: String,
        #[serde(default)]
        expiry_ms: u64,
        #[serde(default)]
        session_pubkey: String,
    },
    /// D193: the sign-in verified; its session needs a certificate in the
    /// member's personal forest. Sent only AFTER the identity's signature
    /// verified (nothing about a member leaks before). The page checks
    /// `binding_sig` — its owner key's own statement that this is its
    /// personal forest on the site `rp_id` — before it signs anything for it.
    SessionCertRequest {
        member: String,
        rp_id: String,
        forest_id: String,
        root_node_id: String,
        binding_sig: String,
        session_pubkey: String,
    },
    /// D193: a remembered session on a new connection — prove the browser
    /// key it is bound to (`BindProof`) before it is restored. PVOS D322:
    /// `key` is that key's public half, so a page holding several (one per
    /// tab's sign-in) signs with the right one; empty from an older pvosd.
    BindChallenge {
        nonce: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        key: String,
    },
    /// Login succeeded — the session token for subsequent `Authed` frames.
    Session { token: String },
    /// D212: this session's grant in the person's own forest — sent after
    /// `Session` (sign-in and restore) and after each renewal, only for a
    /// session that has one. It ends at `ends_ms` (the session with it); from
    /// `renew_from_ms` the page may renew it (`RenewGrant`): silently through
    /// the companion (`via: "companion"`), or after a passkey tap the person
    /// gives (`via: "passkey"`).
    SessionGrant { ends_ms: u64, renew_from_ms: u64, via: String },
    /// D212: the session ended on the server (its grant or its 7-day window
    /// ran out) — the page goes to the sign-in screen and says `reason`.
    SessionEnded { reason: String },
    /// Companion is sealed — the desktop shows "unlock required".
    CompanionLocked,
    /// Apps + grant log (reply to `List`).
    State {
        apps: Vec<AdminAppInfo>,
        records: Vec<AdminGrantInfo>,
    },
    /// A surface to render/update (relayed from the app's `PushViewModel`).
    SurfaceUpdate { app_id: String, surface: String, view_model: serde_json::Value },
    /// Append to a surface's `log` component (relayed from `AppendLog`).
    SurfaceLog {
        app_id: String,
        surface: String,
        component_id: String,
        lines: Vec<String>,
    },
    /// A pending consent to prompt the owner on (doc 16 §3 — the summary is
    /// what the companion will also render/audit).
    ConsentRequest {
        consent_id: u64,
        app_id: String,
        capability: Capability,
        summary: String,
    },
    /// PVOS D209: a pending consent nobody answered in time — its outcome
    /// is `expired` (the asker was answered so, the owner notified). A page
    /// showing this prompt closes it.
    ConsentExpired { consent_id: u64, app_id: String },
    /// A transient notification.
    Toast { level: String, text: String },
    /// The owner's notifications + unread count (M6): pushed on every change and
    /// in reply to `NotificationList`.
    Notifications {
        items: Vec<crate::notify::Notification>,
        unread: usize,
    },
    /// The owner's saved desktop preferences (reply to `GetPrefs`); `json` is
    /// null on first use.
    Prefs { json: Option<String> },
    /// The invite behind a redemption code (D18): what the invitee sees
    /// before their companion signs, and what the companion needs to enroll
    /// this server as paired. Role and capabilities are the SIGNED values,
    /// shown so the invitee knows exactly what they are accepting.
    RedeemChallenge {
        invite_id: String,
        member: String,
        /// The invitee's email as the inviter SIGNED it — shown so the human
        /// accepting can spot a mismatch before their companion signs.
        #[serde(default)]
        email: String,
        role: String,
        capabilities: Vec<String>,
        invited_by: String,
        /// `pvosd`'s paired-server pubkey (hex) + the origins it serves —
        /// the companion binds the pairing to these.
        server_pubkey: String,
        origins: Vec<String>,
        /// D33: browser custody may be offered (the invite carries no
        /// admin-tier capability — the client also needs WebAuthn PRF,
        /// which only the page can know).
        #[serde(default)]
        browser_available: bool,
        /// D36: "join" (default) or "rekey" — the screen says which is
        /// happening; a rekey lands on the existing account and data.
        #[serde(default)]
        rekey: bool,
        /// D193: the key this box will hold in the personal forest the page
        /// makes (hex) — admitted there as a member with NO grant.
        #[serde(default)]
        personal_host: String,
    },
    /// The chain verified: the member is paired and can sign in normally.
    Redeemed { member: String },
    /// D33: a browser member's wrapped-key blob (reply to `BrowserBlobGet`
    /// or `BrowserBlobByCred`) — ciphertext only their passkey can open.
    /// `member` is filled on the by-credential path (that IS how the page
    /// learns whose account the tap chose); empty on the by-name path.
    BrowserBlob {
        blob: String,
        #[serde(default)]
        member: String,
    },
    /// D30: the Settings window's content for THIS session (reply to
    /// `SettingsOp::Get` and pushed after every settings mutation).
    /// Boxed (PVOS D262): the state outgrew every other message, and clippy's
    /// `large_enum_variant` asks for it. The wire is the same.
    Settings { state: Box<SettingsState> },
    /// D280: the Share window. Pushed for a list, a browse, an open folder,
    /// and when a companion approval finishes.
    Share { state: Box<ShareDesktopState> },
    /// D30: an invite minted from Settings completed (the relay signature
    /// landed). `code` is present ONLY when it was NOT emailed — the
    /// mailbox-proof rule (M10) — and this is the one time it is shown.
    InviteMinted {
        member: String,
        email: String,
        role: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        emailed: bool,
        /// D37: a removed member of this name left data — redeeming this
        /// invite REATTACHES it (the CLI already warned; Settings now does
        /// too).
        #[serde(default)]
        reattach_warning: bool,
    },
    /// M10: the session member's email standing — pushed after sign-in and
    /// whenever it changes. The desktop shows a verify banner until
    /// `verified` (or hides email UI entirely when `email` is None and mail
    /// is unconfigured server-side — `can_verify` says whether SENDING is
    /// even possible).
    EmailStatus {
        email: Option<String>,
        verified: bool,
        can_verify: bool,
    },
    /// A typed failure (bad token, unknown app, …).
    Error { code: String, message: String },
    /// Forward this to the companion's loopback `/relay` verbatim (M3.1):
    /// `POST {payload, server_sig}`. `payload` is the exact signed JSON
    /// string; `code` is the 6-digit verification code the page displays
    /// (advisory — the companion re-derives it from the digest, so a lying
    /// server can't make the prompts agree).
    RelayRequest {
        relay_id: u64,
        payload: String,
        server_sig: String,
        code: String,
        /// Whether the 6-digit `code` is a human match element for this relay.
        /// True only when the companion will PROMPT (a `user_action`/consent):
        /// the human compares the code on the companion prompt against the
        /// desktop. A `sign_in` relay from a trusted origin auto-approves with
        /// no prompt (D29), so its code is never shown. Defaults false so an
        /// older desktop simply never flashes it.
        #[serde(default)]
        needs_code: bool,
    },
    /// The answer to a `BridgeCall` (M3.5) — routed by the desktop back into
    /// the originating iframe by `req_id`. `ok` false carries a code/message.
    BridgeReply {
        req_id: u64,
        app_id: String,
        ok: bool,
        #[serde(default)]
        payload: Value,
    },
}

/// D193: a personal forest's genesis as the page built and signed it — the
/// parameters it chose and its five signatures, in log order (three root,
/// two identity). The box rebuilds the same events from these and the keys,
/// attaches the signatures, and keeps the forest only if it replays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalGenesis {
    pub forest_id: String,
    pub instance_id: String,
    pub created_at: u64,
    /// A u64, in decimal: JavaScript numbers cannot carry every u64.
    pub root_nonce: String,
    pub sigs: Vec<String>,
}
