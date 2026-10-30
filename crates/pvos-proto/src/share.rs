//! `pvos.share` wire types (D280). A share link lets someone without PVOS
//! download files. These shapes are what `create`, `list`, `revoke` and
//! `extend` exchange. The log keeps each link, so `list` includes the URL
//! and a row can be stopped. A time limit is optional: `expires` of 0 means
//! the link stays active until it is stopped.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareKind {
    Download,
    /// A friend sends files back. Phase 3; the type is here so the interface
    /// does not gain a second version later.
    Request,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareState {
    Active,
    Revoked,
    Expired,
}

/// One file on a link. `id` is the forest node. `name` and `size` are what
/// the page and the Share app show; the bytes still come from the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedNode {
    pub id: String,
    pub name: String,
    pub size: u64,
}

/// `create`'s argument. `files` and `folder` are exclusive. Uploads are a
/// later phase and have no field here yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateShare {
    pub name: String,
    /// Forest id the nodes live in. One link, one forest.
    pub forest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    pub kind: ShareKind,
    /// Absolute expiry, milliseconds since the epoch. `0` means no time
    /// limit: the link stays active until it is stopped.
    #[serde(default)]
    pub expires: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default)]
    pub e2e: bool,
}

/// Returned at creation. The same URL stays on the log row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedShare {
    pub id: String,
    pub url: String,
}

/// One row of the share log. Active rows sort above expired and stopped
/// ones. `url` is how the owner copies the link again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareSummary {
    pub id: String,
    pub name: String,
    pub url: String,
    pub forest: String,
    pub nodes: Vec<SharedNode>,
    /// Set when the link is a live folder. The page lists that folder's
    /// contents at the moment it is opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<SharedNode>,
    /// `0` means no time limit.
    pub expires: u64,
    pub kind: ShareKind,
    pub e2e: bool,
    /// A password was set. The password itself is not kept.
    pub password: bool,
    pub created_by: String,
    pub created_at: u64,
    pub downloads: u64,
    pub state: ShareState,
}
