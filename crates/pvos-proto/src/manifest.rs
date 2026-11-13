//! App manifest — the app's contract with PVOS, stored signed at
//! `/apps/<id>/manifest`. Wire shape: doc 05 §1.

use serde::{Deserialize, Serialize};

use crate::{AppId, CapKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    User,
    System,
}

/// `"integrated"` | `{"isolated":{"forest":"<ref>"}}` (doc 00 §3.5).
/// Externally tagged gives exactly that shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Residency {
    Integrated,
    Isolated { forest: String },
}

/// `scope_hint` is resolved to a concrete `Scope` at grant time
/// (e.g. `"own-region"` → `/apps/<id>/data`; doc 05 §1 notes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeHint {
    Named(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapRequest {
    pub kind: CapKind,
    pub scope_hint: ScopeHint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapRequests {
    #[serde(default)]
    pub required: Vec<CapRequest>,
    #[serde(default)]
    pub optional: Vec<CapRequest>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// One service method the API may call (PVOS D290). A scheduler callback
/// stays in `methods` and off this list. `companion` means the call waits
/// on the companion; a token cannot name it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiMethod {
    pub name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub companion: bool,
}

/// A service this app offers (behavior plane — empty in M1; doc 06).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDecl {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>, // pvfs:// ref to the interface schema
    #[serde(default)]
    pub methods: Vec<String>,
    /// Methods the CLI and REST may call. Empty means this service has no
    /// API. A grant can still call anything in `methods`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api: Vec<ApiMethod>,
}

/// A service this app consumes; the version constraint drives negotiated
/// upgrade (doc 06, doc 02 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRef {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SurfaceMode {
    Iframe,
    Viewmodel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiSurface {
    pub name: String,
    pub mode: SurfaceMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ui {
    #[serde(default)]
    pub surfaces: Vec<UiSurface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runtime {
    /// `"native"` now; `"wasm"` is the future untrusted-app sandbox tier (D13).
    pub kind: String,
    pub entrypoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Integrity {
    /// Publisher signature over manifest + code (multi-publisher, future).
    /// Today the owner-signed forest write of the manifest + `ui/` nodes is
    /// the integrity guarantee; this stays optional until publisher keys land.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// Content-address (digest) of the app's `ui/` subtree (M3.7 §8b). pvosd
    /// pins this and re-checks the live `/apps/<id>/ui` root against it before
    /// serving assets from the forest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_root: Option<String>,
    /// PVOS D335 — the BLAKE3 hash of the app's program, kept in the forest as
    /// a blob at `/apps/<id>/bin/<seq>-<hash>`. pvosd runs that blob (checked
    /// against this hash), not a file on disk. Set by the install, never by
    /// the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppManifest {
    pub id: AppId,
    pub version: String,
    pub api_version: u32,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>, // "key:<hex>"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// PVOS D209: the app's icon, as a path inside its own `ui/` bundle
    /// (e.g. `"icon.svg"`) — so the bytes are covered by the
    /// `integrity.ui_root` pin and arrive with the install. PNG, JPEG, WebP,
    /// GIF or SVG. (Was documented as a `pvfs://` node ref and never read; a
    /// node ref would have pvosd read any forest node for a browser.)
    pub icon: Option<String>,
    pub tier: Tier,
    pub residency: Residency,
    #[serde(default)]
    pub capabilities: CapRequests,
    #[serde(default)]
    pub node_types: Vec<String>,
    #[serde(default)]
    pub services_provided: Vec<ServiceDecl>,
    #[serde(default)]
    pub services_consumed: Vec<ServiceRef>,
    #[serde(default)]
    pub ui: Ui,
    #[serde(default)]
    pub headless: bool,
    /// D18: this app touches infrastructure (or other admin-tier concerns)
    /// directly and may NEVER be shared below admin — the sharing path
    /// refuses, as a property of the app rather than a policy someone must
    /// remember.
    #[serde(default)]
    pub admin_only: bool,
    /// PVOS D259 — the things a member may be allowed to do in this app, one
    /// grant each (Settings → Members). The app asks `pvos.actors.holds
    /// {actor, app_action}` about its own names only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_actions: Vec<MemberAction>,
    /// D63: minimum daemon protocol versions this app needs. pvosd checks
    /// them at launch and refuses (with a clear message, not a panic) when
    /// the live daemon is below the floor. Absent/zero = no floor beyond
    /// the baseline every daemon has always met.
    #[serde(default)]
    pub requires: Requires,
    pub runtime: Runtime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<Integrity>,
}

/// PVOS D259 — one thing a member may be allowed to do in an app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberAction {
    /// Lower case, 1–32 of `a-z 0-9 _ - .`, starting with a letter.
    pub name: String,
    /// What it lets the member do, in a line (at most 120 characters).
    pub description: String,
}

/// PVOS D259 — the most member actions an app may declare.
pub const MAX_MEMBER_ACTIONS: usize = 32;

/// PVOS D259 — whether `name` is a well-formed member-action name.
pub fn member_action_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 32
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-.".contains(c))
}

/// PVOS D259 — refuse a bad `member_actions` list, with the reason.
pub fn check_member_actions(actions: &[MemberAction]) -> Result<(), String> {
    if actions.len() > MAX_MEMBER_ACTIONS {
        return Err(format!("at most {MAX_MEMBER_ACTIONS} member actions"));
    }
    let mut seen = std::collections::HashSet::new();
    for a in actions {
        if !member_action_name_ok(&a.name) {
            return Err(format!(
                "member action '{}': a name is lower case, 1–32 of a-z 0-9 _ - ., starting with a letter",
                a.name
            ));
        }
        if !seen.insert(a.name.as_str()) {
            return Err(format!("member action '{}' is declared twice", a.name));
        }
        if a.description.trim().is_empty() || a.description.chars().count() > 120 {
            return Err(format!("member action '{}': a description is one line of 1–120 characters", a.name));
        }
    }
    Ok(())
}

/// Minimum daemon protocol versions an app declares (D63). Monotonic
/// integers: the app runs on `installed >= min`. `0` means "any".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requires {
    /// Minimum `pvfs_proto::PROTO_VERSION` (the PVFS wire protocol).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pvfs_proto: u32,
    /// Minimum `pvos_proto::API_VERSION` (the Channel-2 shell↔app contract).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pvos_api: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}
