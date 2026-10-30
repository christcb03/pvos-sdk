//! Behavior-plane shared types (doc 06): service identity/info, call
//! outcomes, and the scheduler's job shapes (doc 07 §2).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capability::ProviderId;

/// A published service as discovery reports it (doc 06 §2). `interface_ref`
/// points at a JSON-Schema description of args/results (D4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub provider: ProviderId,
    pub versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_ref: Option<String>,
}

/// The result of a routed service call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CallOutcome {
    Ok { value: Value },
    Err { code: String, message: String },
}

/// Async-job convention (doc 06 §6.1 / D17): a slow method's `CallOutcome::Ok`
/// value is `{"job_id": "<id>"}`; progress and completion arrive as
/// `ServiceEvent`s on `job/<id>`. The final event has `"done": true`.
pub const JOB_TOPIC_PREFIX: &str = "job/";

// ── scheduler (doc 07 §2) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Schedule {
    /// Fire once at (or as soon after as possible) `at_ms` (epoch ms).
    OneShot { at_ms: u64 },
    /// Fire every `interval_ms`. Without an anchor the first fire is one
    /// interval from registration (M2 behaviour).
    ///
    /// With `first_at_ms` (epoch ms) the fires land on the grid
    /// `first_at_ms + n·interval_ms` — that is how "nightly at 02:00" is
    /// expressed without any server-side timezone or calendar math: the
    /// BROWSER converts the owner's local time to an instant (M4c/D32). An
    /// anchored job's next fire is recomputed from the grid on every load, so
    /// restarts don't make it drift later, and occurrences missed while the
    /// daemon was down are skipped rather than replayed.
    Every {
        interval_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_at_ms: Option<u64>,
    },
}

/// What a job does when it fires: a service call, usually back into the
/// registering app ("call my own service X at time T").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceCallSpec {
    pub provider: ProviderId,
    pub service: String,
    pub method: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Job {
    /// Assigned by the scheduler at `register`; ignored on input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub schedule: Schedule,
    pub action: ServiceCallSpec,
}
