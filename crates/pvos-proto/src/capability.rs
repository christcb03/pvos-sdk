//! Capability descriptors (doc 03 §3, doc 00 §4.2).
//!
//! A capability = `{ kind, scope }`. The wire shape follows the grant JSON in
//! doc 02 §2: `kind` is a lowercase string, `scope` is a variant-shaped object.
//! `covers()` (the per-kind partial order) lives in `pvos-core::capability`,
//! not here — this crate is types only.

use serde::{Deserialize, Serialize};

use crate::NodeId;

/// Capability kinds. `Exec`/`Net` are **bare-metal only** — on a host OS those
/// resources are host-provided, not PVOS-brokered (doc 00 §4.7, review H2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapKind {
    Storage,
    Service,
    Publish,
    Ui,
    Federation,
    Exec,
    Net,
}

/// ACL rights bits, mirroring PVFS: `r`=1, `w`=2, `a`=4.
/// Wire form is the compact string (`"r"`, `"rw"`, `"rwa"`), as in doc 02 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(pub u8);

impl Rights {
    pub const R: u8 = 1;
    pub const W: u8 = 2;
    pub const A: u8 = 4;

    pub fn read(self) -> bool {
        self.0 & Self::R != 0
    }
    pub fn write(self) -> bool {
        self.0 & Self::W != 0
    }
    pub fn admin(self) -> bool {
        self.0 & Self::A != 0
    }
    /// `self` is a subset of `other` (attenuation check building block).
    pub fn subset_of(self, other: Rights) -> bool {
        self.0 & !other.0 == 0
    }

    pub fn as_str(self) -> String {
        let mut s = String::new();
        if self.read() {
            s.push('r');
        }
        if self.write() {
            s.push('w');
        }
        if self.admin() {
            s.push('a');
        }
        s
    }

    pub fn parse(s: &str) -> Result<Rights, String> {
        let mut bits = 0u8;
        for c in s.chars() {
            bits |= match c {
                'r' => Self::R,
                'w' => Self::W,
                'a' => Self::A,
                other => return Err(format!("unknown rights flag '{other}'")),
            };
        }
        Ok(Rights(bits))
    }
}

impl Serialize for Rights {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for Rights {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Rights::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A service's provider identity: `"pvos"` for built-ins, else the provider's
/// authority key as `key:<hex>` (doc 03 §3, doc 06).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderId(pub String);

impl ProviderId {
    pub const PVOS: &'static str = "pvos";
    pub fn pvos() -> Self {
        ProviderId(Self::PVOS.into())
    }
}

/// Provider-defined selector narrowing a `Service` capability (doc 03 §3).
/// Externally tagged: `"all"` | `{"methods":[…]}` | `{"entries":[…]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceSel {
    All,
    Methods(Vec<String>),
    Entries(Vec<String>),
}

/// The per-kind scope payload. Untagged on the wire — the sibling `kind` field
/// discriminates for humans; for serde, each variant's distinct *required*
/// fields discriminate (variants are tried in order; `Federation {}` is kept
/// last since an empty struct matches any object). `Capability::validate()`
/// enforces kind↔scope agreement. Storage uses `node` per the doc 02 §2 JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scope {
    Storage {
        #[serde(rename = "node")]
        root: NodeId,
        rights: Rights,
    },
    Service {
        provider: ProviderId,
        name: String,
        sel: ServiceSel,
    },
    Publish {
        names: Vec<String>,
    },
    Ui {
        surfaces: Vec<String>,
    },
    // bare-metal only:
    Exec {
        programs: Vec<String>,
    },
    Net {
        hosts: Vec<String>,
    },
    /// Region/peer scope — shape TBD with PVFS P4; kept last so untagged
    /// deserialization never shadows the populated variants.
    Federation {},
}

/// A capability: `{ kind, scope }` (doc 03 §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub kind: CapKind,
    pub scope: Scope,
}

impl Capability {
    /// The kind a scope shape implies.
    pub fn scope_kind(scope: &Scope) -> CapKind {
        match scope {
            Scope::Storage { .. } => CapKind::Storage,
            Scope::Service { .. } => CapKind::Service,
            Scope::Publish { .. } => CapKind::Publish,
            Scope::Ui { .. } => CapKind::Ui,
            Scope::Federation { .. } => CapKind::Federation,
            Scope::Exec { .. } => CapKind::Exec,
            Scope::Net { .. } => CapKind::Net,
        }
    }

    /// `kind` and `scope` must agree (the wire carries both; doc 02 §2).
    pub fn validate(&self) -> Result<(), String> {
        let implied = Self::scope_kind(&self.scope);
        if self.kind == implied {
            Ok(())
        } else {
            Err(format!(
                "capability kind {:?} does not match scope shape (implies {:?})",
                self.kind, implied
            ))
        }
    }

    pub fn storage(root: impl Into<NodeId>, rights: Rights) -> Capability {
        Capability {
            kind: CapKind::Storage,
            scope: Scope::Storage {
                root: root.into(),
                rights,
            },
        }
    }
}
