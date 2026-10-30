use std::net::TcpStream;
use std::time::{Duration, Instant};

use pvos_sdk::keys::{crypto, identity::SigningKey};
use pvos_sdk::proto::{DesktopAction, DesktopToServer, RelayOutcome, ServerToDesktop, UiPhase};
use serde_json::Value;
use tungstenite::{Message, WebSocket};

use crate::Result;

pub(crate) fn approve_relay(key: &SigningKey, relay_id: u64, payload: &str) -> Result<DesktopToServer> {
    let payload: Value = serde_json::from_str(payload)?;
    let digest = payload["digest"].as_str().ok_or("a relay with no digest")?;
    let digest: [u8; 32] = hex::decode(digest)?.try_into().map_err(|_| "a digest that is not 32 bytes")?;
    let result = RelayOutcome::Signed {
        pubkey: hex::encode(crypto::pubkey_bytes(key)),
        sig: hex::encode(crypto::sign_digest(key, &digest)?),
    };
    Ok(DesktopToServer::RelayReply { relay_id, result })
}

/// A signed-in desktop: what the browser does, over the same WebSocket.
///
/// The read timeout is generous on purpose: an app's first screens can be real
/// forest writes on a busy machine.
pub struct Desktop {
    ws: WebSocket<TcpStream>,
    token: String,
    key: SigningKey,
}

impl Desktop {
    /// Open the desktop's WebSocket at `addr` and sign in with `key`.
    pub fn sign_in(addr: &str, key: &SigningKey) -> Result<Desktop> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        let (ws, _) = tungstenite::client(format!("ws://{addr}/ws"), stream)
            .map_err(|e| format!("open the desktop at {addr}: {e}"))?;
        let mut desktop = Desktop { ws, token: String::new(), key: key.clone() };
        desktop.send(&DesktopToServer::Login);
        // A paired member signs through the page's relay to their companion, as
        // the browser forwards it; here this process is both.
        loop {
            match desktop.recv() {
                ServerToDesktop::RelayRequest { relay_id, payload, .. } => {
                    desktop.approve(relay_id, &payload)?;
                }
                ServerToDesktop::Session { token } => {
                    desktop.token = token;
                    return Ok(desktop);
                }
                other => return Err(format!("signing in: expected a relay or a session, got {other:?}").into()),
            }
        }
    }

    /// Say yes to a `RelayRequest`, as a member at their companion does: sign its
    /// digest with this member's key.
    pub fn approve(&mut self, relay_id: u64, payload: &str) -> Result<()> {
        let frame = approve_relay(&self.key, relay_id, payload)?;
        self.send(&frame);
        Ok(())
    }

    /// This session's token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Send one frame as it stands.
    pub fn send(&mut self, message: &DesktopToServer) {
        let text = serde_json::to_string(message).expect("a desktop frame serializes");
        self.ws.send(Message::Text(text)).expect("send to the desktop");
    }

    /// Send an action under this session.
    pub fn action(&mut self, action: DesktopAction) {
        let token = self.token.clone();
        self.send(&DesktopToServer::Authed { token, action });
    }

    /// The next frame from the server. `EmailStatus` is an unasked-for push, so
    /// it is skipped.
    pub fn recv(&mut self) -> ServerToDesktop {
        loop {
            match self.ws.read().expect("a desktop frame within the timeout") {
                Message::Text(text) => {
                    let message: ServerToDesktop =
                        serde_json::from_str(&text).expect("a desktop frame parses");
                    if !matches!(message, ServerToDesktop::EmailStatus { .. }) {
                        return message;
                    }
                }
                _ => continue,
            }
        }
    }

    /// Read frames until `pred` says done, up to 40 seconds. Other frames are
    /// dropped.
    pub fn recv_until<T, F: FnMut(ServerToDesktop) -> Option<T>>(&mut self, what: &str, mut pred: F) -> T {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(40) {
            if let Some(found) = pred(self.recv()) {
                return found;
            }
        }
        panic!("timed out waiting for {what}");
    }

    /// Open an app's surface, as its window opening does.
    pub fn open_surface(&mut self, app: &str, surface: &str) {
        self.action(DesktopAction::Surface {
            app_id: app.into(),
            surface: surface.into(),
            phase: UiPhase::Open,
        });
    }

    /// Send a UI event, as a click or a form does.
    pub fn ui_event(&mut self, app: &str, surface: &str, ui_action: &str, payload: Value) {
        self.action(DesktopAction::UiEvent {
            app_id: app.into(),
            surface: surface.into(),
            ui_action: ui_action.into(),
            payload,
        });
    }

    /// The next view pushed to `surface`, as JSON (see [`crate::view`]).
    pub fn next_view(&mut self, app: &str, surface: &str) -> Value {
        self.recv_until(&format!("a view of {app} {surface}"), |message| match message {
            ServerToDesktop::SurfaceUpdate { app_id, surface: s, view_model, .. }
                if app_id == app && s == surface =>
            {
                Some(serde_json::to_value(&view_model).expect("a view serializes"))
            }
            _ => None,
        })
    }

    /// The WebSocket and the session token, for a test that drives frames itself.
    pub fn into_parts(self) -> (WebSocket<TcpStream>, String) {
        (self.ws, self.token)
    }

    /// The underlying WebSocket, for a frame this type has no helper for.
    pub fn websocket(&mut self) -> &mut WebSocket<TcpStream> {
        &mut self.ws
    }
}
