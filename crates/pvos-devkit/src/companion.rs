//! A companion that holds throwaway keys and says yes: only ever beside a forest
//! made for one test. pvosd treats it as any companion, and checks what it signs.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pvos_sdk::keys::identity::SigningKey;
use pvos_sdk::keys::{crypto, envelope};
use pvos_sdk::proto::frame::{read_frame, write_frame};
use pvos_sdk::proto::{AgentRequest, AgentResponse, AGENT_API_VERSION};

pub(crate) fn spawn(
    socket: &Path,
    identity: Arc<SigningKey>,
    encryption: Arc<SigningKey>,
) -> std::io::Result<PathBuf> {
    let listener = UnixListener::bind(socket)?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let (identity, encryption) = (identity.clone(), encryption.clone());
            std::thread::spawn(move || {
                while let Ok(Some(request)) = read_frame::<_, AgentRequest>(&mut stream) {
                    if write_frame(&mut stream, &answer(request, &identity, &encryption)).is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(socket.to_path_buf())
}

fn answer(request: AgentRequest, identity: &SigningKey, encryption: &SigningKey) -> AgentResponse {
    match request {
        AgentRequest::ApiVersion => AgentResponse::ApiVersion { api_version: AGENT_API_VERSION },
        AgentRequest::GetPubkey { role } => {
            let key = if role == "encryption" { encryption } else { identity };
            AgentResponse::Pubkey { pubkey: hex::encode(crypto::pubkey_bytes(key)) }
        }
        AgentRequest::Sign { digest, .. } => match decode_digest(&digest) {
            Some(d) => match crypto::sign_digest(identity, &d) {
                Ok(sig) => AgentResponse::Signature { sig: hex::encode(sig) },
                Err(e) => refused(e),
            },
            None => refused("the digest is not 32 bytes of hex"),
        },
        AgentRequest::SecureUnwrap { ephemeral_pubkey, nonce, wrapped_key } => {
            let wrap = (|| {
                Some(envelope::Wrap {
                    recipient_pubkey: crypto::pubkey_bytes(encryption),
                    ephemeral_pubkey: hex::decode(&ephemeral_pubkey).ok()?,
                    nonce: hex::decode(&nonce).ok()?,
                    wrapped_key: hex::decode(&wrapped_key).ok()?,
                })
            })();
            match wrap.map(|w| envelope::unwrap_content_key(&w, encryption)) {
                Some(Ok(key)) => AgentResponse::ContentKey { content_key: hex::encode(key) },
                Some(Err(e)) => refused(e),
                None => refused("the wrap is not hex"),
            }
        }
        AgentRequest::Pair { .. } => {
            AgentResponse::Paired { identity_pubkey: hex::encode(crypto::pubkey_bytes(identity)) }
        }
        AgentRequest::ListPairings => AgentResponse::Pairings { pairings: vec![] },
        AgentRequest::RevokePairing { .. } | AgentRequest::Lock => AgentResponse::Ok,
    }
}

fn refused(why: impl std::fmt::Display) -> AgentResponse {
    AgentResponse::Error { code: "denied".into(), message: why.to_string() }
}

fn decode_digest(digest: &str) -> Option<[u8; 32]> {
    hex::decode(digest).ok()?.try_into().ok()
}
