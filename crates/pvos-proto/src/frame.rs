//! Wire framing: `u32 length (LE) || JSON body` (doc 04 §2, same as PVFS doc 07).
//! Generic over `std::io::{Read, Write}` — no sockets here.

use std::io::{self, Read, Write};

use serde::{de::DeserializeOwned, Serialize};

/// Refuse frames larger than this (defense against a bad/hostile peer).
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|l| *l <= MAX_FRAME)
        .ok_or_else(|| io::Error::other("frame exceeds MAX_FRAME"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one frame. `Ok(None)` = clean EOF before a frame started.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(io::Error::other(format!("frame length {len} exceeds MAX_FRAME")));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map(Some).map_err(io::Error::other)
}
