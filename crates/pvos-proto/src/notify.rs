//! `pvos.notify` wire types (M6, D33). A notification is a **record**; a toast
//! is a hint. These shapes cross both channels: apps post over the control
//! socket, the desktop reads and acknowledges over the websocket.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    #[default]
    Info,
    Success,
    Warn,
    Error,
}

impl Level {
    pub fn parse(s: &str) -> Level {
        match s {
            "success" => Level::Success,
            "warn" => Level::Warn,
            "error" => Level::Error,
            _ => Level::Info,
        }
    }
}

/// Where clicking a notification should take the owner: an app surface, plus an
/// opaque key the app interprets (a run id, a host name — the OS doesn't care).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyRef {
    pub app_id: String,
    pub surface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    /// Monotonic within a store — orders the list without trusting clocks.
    pub seq: u64,
    /// Which app emitted it.
    pub app: String,
    pub level: Level,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// `ref` on the wire (the design's name, and what apps post); `reference`
    /// in Rust because `ref` is a keyword.
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<NotifyRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedupe_key: Option<String>,
    pub created_ms: u64,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub dismissed: bool,
    /// How many times this collapsed occurrence has happened (dedupe).
    #[serde(default = "one")]
    pub count: u32,
    /// Whose notification this is (D18 slice 4). Default `"owner"`, so every
    /// pre-D18 record keeps meaning what it meant. Notifications are personal
    /// by definition (§3') — there is no shared inbox.
    #[serde(default = "owner")]
    pub member: String,
}

fn owner() -> String {
    "owner".into()
}

fn one() -> u32 {
    1
}
