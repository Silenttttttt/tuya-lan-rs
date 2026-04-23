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
pub fn aes_gcm_encrypt(plaintext: &[u8], key: &[u8; 16], iv: &[u8; 12], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::Payload;
    let cipher = Aes128Gcm::new(key.into());
    let nonce = Nonce::from_slice(iv);
    cipher.encrypt(nonce, Payload { msg: plaintext, aad }).ok()
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
