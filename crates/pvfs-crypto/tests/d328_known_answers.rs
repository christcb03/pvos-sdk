//! D328 — known answers across the k256 0.13 → 0.14 upgrade
//! (PVOS docs/milestones/D328-dependency-updates.md).
//!
//! Every constant below was produced by the code BEFORE the upgrade (k256
//! 0.13, bip32 0.5). The same assertions must hold after it: the phrase
//! derives the same keys, a signature made then still verifies (and a new one
//! is byte-identical, RFC 6979), a high-s signature is still refused, a raw
//! device key still loads, and — the one that matters most — an envelope
//! sealed then still opens, so no secret sealed before the upgrade is lost.
//!
//! `D328_PRINT=1 cargo test -p pvfs-crypto --test d328_known_answers -- --nocapture`
//! prints the current values instead of checking them.

use pvfs_crypto::{crypto, envelope, identity};

/// BIP39's all-zero 256-bit entropy vector.
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";
const DIGEST: [u8; 32] = [0x42; 32];
const PLAINTEXT: &[u8] = b"D328 known answer: sealed before the k256 upgrade";

const ROOT_PUB: &str = "036242fd83e40688fc2c61fa05061edc98fef9bf2e4c85c28718b9d5f4f6acd2ac";
const DEVICE0_PUB: &str = "02c3a30e05b8c44bf16f0fcec80f481954acb45984d6ff6d6b0766385362092656";
const IDENTITY0_PUB: &str = "036435e78bcc147f4c92e0db70d4107d0c5bf04b169cf1b3d339212088df21a544";
const ENCRYPTION0_PUB: &str = "03d02843b4ffdfe3ae8a18feb3a9a2e6a4d5cc39150f2e8d9990da1b281355d744";
const DEVICE0_SECRET: &str = "5523fbac6a62e00939fb52c87750797fbdc812833ef1b2bd8c67c67e6fb540c8";
const DEVICE0_SIG: &str = concat!(
    "99edd73b832f96f6a09110d275f2ada6cde3364db8cc45c35518c4da544cd89679740ea390bf5ca4",
    "d2ba479a8739a1e877c667b3482e397b83e79d285dfe8666",
);
const SEALED_FOR_ENCRYPTION0: &str = concat!(
    "010000000000000001000000000000002100000003d02843b4ffdfe3ae8a18feb3a9a2e6a4d5cc39",
    "150f2e8d9990da1b281355d7442100000002195832b92945e7056fe55d9eb86de795cc77259b4291",
    "84525faf13e43344e3d318000000cac47f2c3bb51519c13d335e4adea933c5d626b44f8cf0843000",
    "0000ebef5982b373c483a0243be0860ebc596e6bab6555faa42a2ca05974354e12a32ce5d94ded42",
    "2d63849871ebe98e279618000000adc028043eb8fbe40f9dc883d2f3e1b4b1f518722677242a4100",
    "0000cc76c7320f12153d873183f56cc8d236b2e8e5907c7113c20738f183fc3f2ac506c00ac33e5a",
    "25a32d3257bafab57b9ab9c478b6c40fefec4a2455a74ee57d3c5e",
);

fn printing() -> bool {
    std::env::var("D328_PRINT").is_ok()
}

fn check(name: &str, actual: &str, expected: &str) {
    if printing() {
        println!("const {name}: &str = \"{actual}\";");
    } else {
        assert_eq!(actual, expected, "{name} changed across the upgrade");
    }
}

fn mnemonic() -> identity::Mnemonic {
    identity::parse_mnemonic(PHRASE).expect("the BIP39 vector parses")
}

#[test]
fn the_phrase_derives_the_same_keys() {
    let m = mnemonic();
    let pubhex = |k: &identity::SigningKey| hex::encode(crypto::pubkey_bytes(k));
    check("ROOT_PUB", &pubhex(&identity::root_key(&m, "").unwrap()), ROOT_PUB);
    check("DEVICE0_PUB", &pubhex(&identity::device_key(&m, "", 0).unwrap()), DEVICE0_PUB);
    check("IDENTITY0_PUB", &pubhex(&identity::identity_key(&m, "", 0).unwrap()), IDENTITY0_PUB);
    check(
        "ENCRYPTION0_PUB",
        &pubhex(&identity::encryption_key(&m, "", 0).unwrap()),
        ENCRYPTION0_PUB,
    );
    check(
        "DEVICE0_SECRET",
        &hex::encode(identity::device_key(&m, "", 0).unwrap().to_bytes()),
        DEVICE0_SECRET,
    );
}

#[test]
fn a_raw_device_key_still_loads() {
    if printing() {
        return;
    }
    let raw = hex::decode(DEVICE0_SECRET).unwrap();
    let key = identity::SigningKey::from_slice(&raw).expect("a stored device key loads");
    assert_eq!(hex::encode(crypto::pubkey_bytes(&key)), DEVICE0_PUB);
}

#[test]
fn signatures_are_unchanged() {
    let key = identity::device_key(&mnemonic(), "", 0).unwrap();
    let sig = crypto::sign_digest(&key, &DIGEST).unwrap();
    check("DEVICE0_SIG", &hex::encode(&sig), DEVICE0_SIG);
    if printing() {
        return;
    }
    let author = hex::decode(DEVICE0_PUB).unwrap();
    let old = hex::decode(DEVICE0_SIG).unwrap();
    crypto::verify_digest(&author, &DIGEST, &old).expect("a signature made before verifies");

    // The malleable twin (s → n − s) is refused, as before.
    let high = high_s(&old);
    assert!(
        crypto::verify_digest(&author, &DIGEST, &high).is_err(),
        "a high-s signature must be refused"
    );
    // And a wrong digest fails.
    assert!(crypto::verify_digest(&author, &[0x43; 32], &old).is_err());
}

#[test]
fn an_envelope_sealed_before_still_opens() {
    let enc = identity::encryption_key(&mnemonic(), "", 0).unwrap();
    if printing() {
        let sealed = envelope::seal(PLAINTEXT, &[crypto::pubkey_bytes(&enc)]).unwrap();
        println!("const SEALED_FOR_ENCRYPTION0: &str = \"{}\";", hex::encode(sealed));
        return;
    }
    let env = envelope::parse(&hex::decode(SEALED_FOR_ENCRYPTION0).unwrap()).unwrap();
    let wrap = env
        .wraps
        .iter()
        .find(|w| hex::encode(&w.recipient_pubkey) == ENCRYPTION0_PUB)
        .expect("a wrap for the encryption key");
    let content_key = envelope::unwrap_content_key(wrap, &enc).expect("ECDH gives the same KEK");
    assert_eq!(envelope::open_with_key(&env, &content_key).unwrap(), PLAINTEXT);

    // And what the new code seals, it opens.
    let fresh = envelope::seal(PLAINTEXT, &[crypto::pubkey_bytes(&enc)]).unwrap();
    let env = envelope::parse(&fresh).unwrap();
    let ck = envelope::unwrap_content_key(&env.wraps[0], &enc).unwrap();
    assert_eq!(envelope::open_with_key(&env, &ck).unwrap(), PLAINTEXT);
}

/// r ‖ (n − s): the same signature with its high-s twin.
fn high_s(sig: &[u8]) -> Vec<u8> {
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let s = &sig[32..64];
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = N[i] as i16 - s[i] as i16 - borrow;
        borrow = if d < 0 {
            d += 256;
            1
        } else {
            0
        };
        out[i] = d as u8;
    }
    let mut v = sig[..32].to_vec();
    v.extend_from_slice(&out);
    v
}
