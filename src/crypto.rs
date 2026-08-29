use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use sha2::Sha256;

type HmacSha256 = hmac::Hmac<Sha256>;

/// AES-128-ECB encrypt in-place (protocol 3.4).
pub fn aes_ecb_encrypt(data: &mut [u8], key: &[u8; 16]) {
    let cipher = Aes128::new(key.into());
    for chunk in data.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
}

/// AES-128-ECB decrypt in-place (protocol 3.4).
pub fn aes_ecb_decrypt(data: &mut [u8], key: &[u8; 16]) {
    let cipher = Aes128::new(key.into());
    for chunk in data.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
}

/// AES-128-GCM encrypt. Returns ciphertext + 16-byte tag appended.
pub fn aes_gcm_encrypt(
    plaintext: &[u8],
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
) -> Option<Vec<u8>> {
    use aes_gcm::aead::Payload;
    let cipher = Aes128Gcm::new(key.into());
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .ok()
}

/// AES-128-GCM decrypt. `data` = ciphertext + 16-byte tag.
pub fn aes_gcm_decrypt(data: &[u8], key: &[u8; 16], iv: &[u8; 12], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::Payload;
    if data.len() < 16 {
        return None;
    }
    let cipher = Aes128Gcm::new(key.into());
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, Payload { msg: data, aad }).ok()
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("HMAC key");
    hmac::Mac::update(&mut mac, data);
    let result = hmac::Mac::finalize(mac);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Derive session key: XOR local and remote nonces, then encrypt with device key.
/// Protocol 3.4 uses ECB; 3.5 uses GCM.
pub fn derive_session_key(
    local_nonce: &[u8; 16],
    remote_nonce: &[u8; 16],
    device_key: &[u8; 16],
    version: u8,
) -> [u8; 16] {
    let mut xor_key = [0u8; 16];
    for i in 0..16 {
        xor_key[i] = local_nonce[i] ^ remote_nonce[i];
    }

    if version <= 4 {
        aes_ecb_encrypt(&mut xor_key, device_key);
    } else {
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&local_nonce[..12]);
        if let Some(encrypted) = aes_gcm_encrypt(&xor_key, device_key, &iv, &[]) {
            xor_key.copy_from_slice(&encrypted[..16]);
        }
    }

    xor_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_round_trip_recovers_plaintext() {
        let key = [0x42u8; 16];
        let mut data = *b"0123456789abcdef"; // exactly one 16-byte block
        let original = data;
        aes_ecb_encrypt(&mut data, &key);
        assert_ne!(data, original, "ciphertext should differ from plaintext");
        aes_ecb_decrypt(&mut data, &key);
        assert_eq!(data, original, "decrypt(encrypt(x)) must recover x");
    }

    #[test]
    fn gcm_round_trip_recovers_plaintext() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let aad = b"header bytes as aad";
        let plaintext = b"real tuya dps payload {\"20\":true}";

        let ciphertext = aes_gcm_encrypt(plaintext, &key, &iv, aad).expect("encrypt succeeds");
        assert_ne!(
            &ciphertext[..plaintext.len()],
            plaintext,
            "ciphertext must not equal plaintext"
        );

        let decrypted = aes_gcm_decrypt(&ciphertext, &key, &iv, aad).expect("decrypt succeeds");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn gcm_decrypt_rejects_wrong_aad() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let ciphertext = aes_gcm_encrypt(b"secret", &key, &iv, b"correct aad").unwrap();
        assert!(
            aes_gcm_decrypt(&ciphertext, &key, &iv, b"wrong aad").is_none(),
            "AEAD must reject a valid ciphertext presented with the wrong associated data"
        );
    }

    #[test]
    fn gcm_decrypt_rejects_tampered_ciphertext() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let mut ciphertext = aes_gcm_encrypt(b"secret", &key, &iv, b"aad").unwrap();
        ciphertext[0] ^= 0xFF;
        assert!(aes_gcm_decrypt(&ciphertext, &key, &iv, b"aad").is_none());
    }

    #[test]
    fn hmac_sha256_matches_known_vector() {
        // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?"
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn derive_session_key_v34_is_symmetric_in_the_xor_inputs() {
        // Protocol 3.4's path (plain ECB, no IV) only ever consumes local_nonce ^ remote_nonce --
        // since XOR is commutative and ECB has no IV to depend on which side called which nonce
        // "local", swapping the two arguments must reproduce the identical key.
        let a_nonce = [0x01u8; 16];
        let b_nonce = [0x02u8; 16];
        let device_key = [0x03u8; 16];

        let key_a = derive_session_key(&a_nonce, &b_nonce, &device_key, 4);
        let key_b = derive_session_key(&b_nonce, &a_nonce, &device_key, 4);
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn derive_session_key_v35_is_deterministic_but_not_swap_symmetric() {
        // Protocol 3.5's path additionally uses `local_nonce[..12]` as the GCM IV -- so unlike
        // 3.4, swapping which nonce is "local" changes the IV and therefore the derived key.
        // This is fine in practice (the real client always calls this with the SAME fixed
        // LOCAL_NONCE constant as `local_nonce`, per session.rs -- there's no actual swap in the
        // real handshake), but it's a real, non-obvious difference from the 3.4 path worth
        // documenting via a test rather than an assumption. What DOES need to hold: calling this
        // twice with the exact same inputs must always produce the exact same key (no hidden
        // randomness) -- confirmed here.
        let a_nonce = [0x01u8; 16];
        let b_nonce = [0x02u8; 16];
        let device_key = [0x03u8; 16];

        let key_again = derive_session_key(&a_nonce, &b_nonce, &device_key, 5);
        let key_again2 = derive_session_key(&a_nonce, &b_nonce, &device_key, 5);
        assert_eq!(
            key_again, key_again2,
            "must be deterministic for identical inputs"
        );

        let swapped = derive_session_key(&b_nonce, &a_nonce, &device_key, 5);
        assert_ne!(
            key_again, swapped,
            "v3.5 intentionally is NOT swap-symmetric (IV depends on which nonce is local) -- \
             if this ever starts passing, something about the IV handling changed"
        );
    }
}
