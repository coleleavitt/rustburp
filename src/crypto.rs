use anyhow::Result;
use cipher::KeyInit;
use des::Des;
use ecb::{Decryptor, Encryptor};

type DesEcbEnc = Encryptor<Des>;
type DesEcbDec = Decryptor<Des>;

/// DES encryption key used by Burp Suite
const ENCRYPTION_KEY: &[u8; 8] = b"burpr0x!";

/// Encrypt data using DES ECB mode (matching Java implementation)
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>> {
    use cipher::BlockEncryptMut;

    // PKCS5/PKCS7 padding
    let block_size = 8;
    let padding_len = block_size - (data.len() % block_size);
    let padded_len = data.len() + padding_len;

    let mut padded = vec![padding_len as u8; padded_len];
    padded[..data.len()].copy_from_slice(data);

    // Encrypt in place
    let encryptor = DesEcbEnc::new(ENCRYPTION_KEY.into());

    // Process each block
    let mut encrypted = padded;
    for chunk in encrypted.chunks_mut(8) {
        let block = cipher::Block::<Des>::from_mut_slice(chunk);
        encryptor.clone().encrypt_block_mut(block);
    }

    Ok(encrypted)
}

/// Decrypt data using DES ECB mode
pub fn decrypt(data: &[u8]) -> Result<Vec<u8>> {
    use cipher::BlockDecryptMut;

    if data.len() % 8 != 0 {
        anyhow::bail!("Invalid ciphertext length: must be multiple of 8");
    }

    let decryptor = DesEcbDec::new(ENCRYPTION_KEY.into());

    // Decrypt in place
    let mut decrypted = data.to_vec();
    for chunk in decrypted.chunks_mut(8) {
        let block = cipher::Block::<Des>::from_mut_slice(chunk);
        decryptor.clone().decrypt_block_mut(block);
    }

    // Remove PKCS5/PKCS7 padding
    if let Some(&padding_len) = decrypted.last() {
        let padding_len = padding_len as usize;
        if padding_len > 0 && padding_len <= 8 && decrypted.len() >= padding_len {
            // Verify padding
            let valid_padding = decrypted[decrypted.len() - padding_len..]
                .iter()
                .all(|&b| b as usize == padding_len);
            if valid_padding {
                decrypted.truncate(decrypted.len() - padding_len);
            }
        }
    }

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = b"Hello, Burp Suite!";
        let encrypted = encrypt(original).unwrap();
        let decrypted = decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_decrypt_exact_block() {
        let original = b"12345678"; // Exactly 8 bytes
        let encrypted = encrypt(original).unwrap();
        let decrypted = decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }
}
