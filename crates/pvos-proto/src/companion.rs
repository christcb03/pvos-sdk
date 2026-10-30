//! Companion agent wire types — a faithful mirror of
//! `pvfs_companion::proto` (PVFS doc 16 §1, the pinned joint agent API).
//!
//! We mirror rather than depend on `pvfs-companion` because that crate's
//! default features pull `keyring` + libdbus — too heavy to drag through the
//! whole PVOS build for a handful of stable JSON types. Doc 16 is the
//! contract; [`AGENT_API_VERSION`] is the MINIMUM companion version we need
//! (the API evolves additively — doc 16 says callers check `ApiVersion`
//! before relying on newer ops), and `pvos-core`'s client negotiates it at
//! connect (an older companion is a hard error, so drift surfaces
//! immediately rather than corrupting a signature).
//!
//! Framing on the agent socket is `u32 LE length ‖ JSON` — identical to our
//! [`crate::frame`], so the same reader/writer speaks it byte-for-byte.

use serde::{Deserialize, Serialize};

/// Minimum `pvfs_companion::proto::API_VERSION` we require (doc 16 §7
/// item 4). v2: pairing + the browser-relay envelope (M3.1). v3: key-trust
/// pairing + auto sign-in (D27/D29) — everything the keychain's
/// `secure_unwrap` path uses. Newer companions are additive, so `>=` is the
/// accept rule (see `pvos-core`'s `check_version`).
pub const AGENT_API_VERSION: u32 = 3;

/// Domain prefix for the relay envelope signature (mirror of the companion's
/// `RELAY_DOMAIN`): the paired server signs
/// `domain_digest(RELAY_DOMAIN, payload_json_bytes)`.
pub const RELAY_DOMAIN: &str = "pvfs:relay:v1:";

/// The 6-digit verification code both screens display (M3.1 §4.3). Mirror of
/// the companion's `verify_code`; the web renderer derives the same digits.
pub fn verify_code(digest: &[u8; 32]) -> String {
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{n:06}")
}

/// The relayed request a paired server signs (M3.1). Transmitted as the exact
/// JSON string the signature covers — no canonicalization. Mirror of the
/// companion's (PVFS `pvfs-companion` proto.rs).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RelayPayload {
    /// `"sign_in"`, `"user_action"`, or (D193) `"session_cert"`,
    /// `"personal_genesis"`, `"confirm"`.
    pub kind: String,
    /// The paired server's pubkey (hex) — selects the pairing to verify with.
    pub server_pubkey: String,
    /// The 32-byte digest (hex) to sign. D193: a `sign_in` also carries its
    /// `login` fields — a D193 companion builds the digest from them and
    /// refuses a digest that is not theirs; an older one signs this.
    #[serde(default)]
    pub digest: String,
    /// Required for `user_action`; optional for sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ApprovalContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginFields>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_cert: Option<SessionCertFields>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis: Option<GenesisFields>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ConfirmFields>,
}

/// D193: a sign-in's fields (pvos-core `login_digest` v2 inputs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginFields {
    pub nonce: String,
    pub instance_id: String,
    pub expiry_ms: u64,
    pub session_pubkey: String,
}

/// D193: a session certificate to make — and the binding that says the
/// forest is the member's own on this site. The companion picks the times.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCertFields {
    pub member: String,
    pub rp_id: String,
    pub forest_id: String,
    pub root_node_id: String,
    pub binding_sig: String,
    pub session_pubkey: String,
}

/// D193: a personal forest to make for `member`, hosted by the box whose key
/// is `host_pub`. The companion picks the forest's parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisFields {
    pub member: String,
    pub host_pub: String,
}

/// D193: a delete or a grant to confirm — the companion writes the words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmFields {
    pub op: String,
    pub subject: String,
    #[serde(default)]
    pub detail: String,
    pub instance_id: String,
    pub nonce: String,
    pub expiry_ms: u64,
}

/// A pairing as reported by `ListPairings` (all public data).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairingInfo {
    pub name: String,
    pub server_pubkey_hex: String,
    pub origins: Vec<String>,
    pub created_ms: u64,
}

/// The human-approval context a trusted broker binds to a digest (doc 16 §3.1).
/// `pvosd` composes it from the *same operation* it computed the digest from,
/// so the prompt cannot lie about what is signed. The app never supplies the
/// digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalContext {
    /// The authenticated app's id (the broker fills it — unforgeable).
    pub app_id: String,
    /// A verb from the controlled vocabulary (`grant`, `revoke`, `install`, …).
    pub action: String,
    /// One human-readable line the broker composed from the operation.
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// What will be signed, computed by the broker. When present it must equal
    /// the request's `digest` — the companion refuses a mismatch (`bad_input`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_hex: Option<String>,
}

/// Request to the companion agent (`op`-tagged, snake_case — doc 16 §1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentRequest {
    /// Protocol version — answered even while locked.
    ApiVersion,
    /// Public key for a role: `"root"` or `"identity"`.
    GetPubkey { role: String },
    /// Sign a 32-byte digest (hex). `request_type` selects key + approval tier
    /// (`root_device_cert` | `identity_tag` | `identity_assertion` |
    /// `user_action`); `origin` is `"local"` | `"web"`.
    Sign {
        request_type: String,
        digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<ApprovalContext>,
    },
    Lock,
    /// Unwrap a secure-blob content key (PVFS doc 12 §8.5, the P3 envelope):
    /// the wrap's fields (hex); answers `ContentKey`. Local-only,
    /// auto-while-unlocked tier — the encryption key never leaves the
    /// companion. Used by the keychain (M5) to open entry payloads.
    SecureUnwrap {
        ephemeral_pubkey: String,
        nonce: String,
        wrapped_key: String,
    },
    /// Enroll a paired server (M3.1; socket-only, human-prompted). Answers
    /// `Paired{identity_pubkey}` — the key the server stores and verifies
    /// relayed answers against.
    Pair {
        name: String,
        server_pubkey: String,
        origins: Vec<String>,
    },
    ListPairings,
    RevokePairing { name: String },
}

/// The agent's reply (`status`-tagged, snake_case).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentResponse {
    ApiVersion { api_version: u32 },
    Pubkey { pubkey: String },
    Signature { sig: String },
    Paired { identity_pubkey: String },
    Pairings { pairings: Vec<PairingInfo> },
    /// A recovered secure-blob content key (hex), from `SecureUnwrap`.
    ContentKey { content_key: String },
    Ok,
    Error { code: String, message: String },
}

/// Well-known `request_type` values (doc 16 §2).
pub mod request_type {
    pub const ROOT_DEVICE_CERT: &str = "root_device_cert";
    pub const IDENTITY_TAG: &str = "identity_tag";
    pub const IDENTITY_ASSERTION: &str = "identity_assertion";
    /// The D19 human-attributed action — desktop consent + owner mutations.
    pub const USER_ACTION: &str = "user_action";
}
