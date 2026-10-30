//! `pvos-proto` — shared wire types & protocol definitions for PVOS.
//!
//! Pure types, no network I/O (the `frame` module works over generic `Read`/`Write`).
//! Mirrors `pvfs-proto`. Defines the Channel-2 control-socket message set,
//! the app manifest, capability/scope descriptors, and grant encodings.
//! See `docs/04-control-socket-protocol.md` and `docs/03-pvos-core-and-types.md`.
//!
//! M1 scope (docs/milestones/M1-build-checklist.md §1): capability + grant +
//! manifest types, and the minimal control-socket subset (attach + `GetContext`).

pub mod api;
pub mod behavior;
pub mod capability;
pub mod companion;
pub mod control;
pub mod desktop;
pub mod frame;
pub mod grant;
pub mod manifest;
pub mod notify;
pub mod share;
pub mod viewmodel;

pub use behavior::{
    CallOutcome, Job, Schedule, ServiceCallSpec, ServiceInfo, JOB_TOPIC_PREFIX,
};
pub use capability::{CapKind, Capability, ProviderId, Rights, Scope, ServiceSel};
pub use companion::{
    verify_code, AgentRequest, AgentResponse, ApprovalContext, ConfirmFields, GenesisFields, LoginFields,
    PairingInfo, RelayPayload, SessionCertFields, AGENT_API_VERSION, RELAY_DOMAIN,
};
pub use control::{
    auth_digest, AdminAppInfo, AdminGrantInfo, ApiMethodInfo, ApiTokenInfo, CapChange, ClientMsg,
    Context, InviteInfo,
    MemberInfo, ServerMsg, SessionInfo, UiFile, UiPhase, ADMIN_APP_ID, API_VERSION,
    MAX_UI_BUNDLE_BYTES, OP_INSTALL_APP,
};
pub use desktop::{BridgeOp, DesktopAction, DesktopToServer, RelayOutcome, ServerToDesktop};
pub use grant::{Depth, Grant, GrantId, GrantRecord, Issuer, Subject};
pub use manifest::{
    ApiMethod, AppManifest, CapRequest, Integrity, Residency, Runtime, ScopeHint, ServiceDecl,
    ServiceRef, Tier, UiSurface,
};
pub use share::{CreateShare, CreatedShare, ShareKind, ShareState, ShareSummary, SharedNode};
pub use viewmodel::{
    AlertLevel, Card, Component, DiagramChip, DiagramCluster, DiagramEdge, DiagramNode, FileCommand,
    FileCrumb, FileEntry, FilePlace, RowButton, ViewModel,
};

/// PVFS node id (hex string, opaque to PVOS).
pub type NodeId = String;
/// Milliseconds since the Unix epoch (doc 03 §3).
pub type Timestamp = u64;
/// Stable application id (reverse-DNS for store apps; any local id for side-loads).
pub type AppId = String;
/// A public key on the wire: lowercase hex of the 33-byte compressed secp256k1 key.
pub type KeyHex = String;
