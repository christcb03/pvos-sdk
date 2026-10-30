//! Grant records — persisted as signed nodes in `/grants` (owner-issued) or
//! `/apps/<id>/grants` (app-issued delegations). Wire shape: doc 02 §2.
//!
//! `author` + `sig` are NOT fields here: they live in the PVFS event the
//! record is written as (two-phase member write; doc 03 §5). Timestamps are
//! ms-since-epoch (`Timestamp`, doc 03 §3); the ISO strings in the doc 02
//! example are illustrative.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{AppId, Capability, KeyHex, Timestamp};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GrantId(pub String);

/// Who receives the authority. Wire form: `"app:<id>"` | `"key:<hex>"` |
/// `"role:<name>"` (D18: "shared with every member holding this role" — an
/// ordinary grant, not a second ACL system).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    App(AppId),
    Key(KeyHex),
    Role(String),
}

/// The authority that issued the record. Wire form: `"owner"` | `"app:<id>"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issuer {
    Owner,
    App(AppId),
}

/// Re-delegation budget: `0` = non-delegable; `N` = children get ≤ N−1;
/// `"unlimited"` allowed (doc 02 §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    N(u32),
    Unlimited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    pub subject: Subject,
    pub capability: Capability,
    pub issuer: Issuer,
    pub redelegation_depth: Depth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<Timestamp>,
    pub issued_at: Timestamp,
}

/// A `/grants` (or `/apps/<id>/grants`) entry: a grant or a revocation.
/// Internally tagged: `{"type":"grant", …}` | `{"type":"revoke", …}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum GrantRecord {
    Grant(Grant),
    Revoke { grant: GrantId, at: Timestamp },
}

// ── string encodings ────────────────────────────────────────────────────────

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::App(id) => write!(f, "app:{id}"),
            Subject::Key(k) => write!(f, "key:{k}"),
            Subject::Role(r) => write!(f, "role:{r}"),
        }
    }
}

impl Subject {
    pub fn parse(s: &str) -> Result<Subject, String> {
        if let Some(id) = s.strip_prefix("app:") {
            Ok(Subject::App(id.into()))
        } else if let Some(k) = s.strip_prefix("key:") {
            Ok(Subject::Key(k.into()))
        } else if let Some(r) = s.strip_prefix("role:") {
            Ok(Subject::Role(r.into()))
        } else {
            Err(format!(
                "subject must be 'app:<id>', 'key:<hex>' or 'role:<name>', got '{s}'"
            ))
        }
    }
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Issuer::Owner => f.write_str("owner"),
            Issuer::App(id) => write!(f, "app:{id}"),
        }
    }
}

impl Issuer {
    pub fn parse(s: &str) -> Result<Issuer, String> {
        if s == "owner" {
            Ok(Issuer::Owner)
        } else if let Some(id) = s.strip_prefix("app:") {
            Ok(Issuer::App(id.into()))
        } else {
            Err(format!("issuer must be 'owner' or 'app:<id>', got '{s}'"))
        }
    }
}

impl Serialize for Subject {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Subject::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Issuer {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for Issuer {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Issuer::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Depth {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Depth::N(n) => s.serialize_u32(*n),
            Depth::Unlimited => s.serialize_str("unlimited"),
        }
    }
}
impl<'de> Deserialize<'de> for Depth {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u32),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => Ok(Depth::N(n)),
            Raw::S(s) if s == "unlimited" => Ok(Depth::Unlimited),
            Raw::S(s) => Err(serde::de::Error::custom(format!(
                "depth must be a number or \"unlimited\", got \"{s}\""
            ))),
        }
    }
}
