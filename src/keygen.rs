use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;

use rsa::{BigUint, RsaPrivateKey};
use sha1::Sha1;
use sha2::Sha256;

use crate::crypto;

/// RSA 2048-bit private key components (extracted from Java PKCS#8)
/// These are the raw BigInteger hex values for modulus and private exponent
const MODULUS_2048: &str = "9D9DF9EB49890DE8F193C89598584BC947BA83727B2D89AA8BE3A4689130FE2E948967D40B656762F9989E59C9655E28E33FD4B4A544126FDD90A566BB61C2D7C74A6829265767B56E28FD2214D4BEB3B1DA4722BC394E2E6AFA0F1689FA9DB442643DDDA84997C5AD15B57EE5BD1A357CABF6ED4CAAA5FB8872E07C8F5FAE1C573C1214DD273C6D8887D7E993208D75118CC2305D60AA337B0999B69988322A8FAA9FBFF49AB70B71723E1CBD79D12640AF19E6FBC28C05E6630414DBAD9AEF912D0AC53E40B7F48EE29BFE1DEFCFB0BDB1B6C5BF8B06DCCA15FA1FC3F468952D481070C92C386D3CE6187B062038A6CA822D352ECEBEAC195918F9BB5C3AC3";
const PRIV_EXP_2048: &str = "5DAD71C754BA3F692E835E1903259F4D6EF33C82C3110A9C316E47DDDA455B1D062D306787AA6A2B1A1B8A29E517F941A5E6DF1DCA87CDC96CCF366EFB799C1B31185915F3F2C8F1BD1A61706B1F1284AC7506087004432235748F991EC2B40E59D3482DC08294D0E9115900A5BCA1A21E89FA45896677262B2FD39A54805273162D655F1AB4392CE4E01A4DD63F7EF387B79D53B73BBE45EA7D9BE64A627CFB3DAE2843E85ED3697672BD4832F5EEB4C18C4D15FEB550E0B5A7018A3CD39A9FD4BDA35A6F88BD00CCBC787419AD57C54FA823EC3D7662710B03C2622E9E2DE546B21CA1C76672B1CC6BD92871A0F96051E31CB060E0DDB4022BEB2897A88761";

/// RSA 1024-bit private key components
const MODULUS_1024: &str = "8D187233EB87AB60DB5BAE8453A7DE035428EB177EC8C60341CAB4CF487052751CA8AFF226EA3E98F0CEEF8AAE12E3716B8A20A24BDE20703865C9DBD9543F92EA6495763DFD6F7507B8607F2A14F52694BB9793FE12D3D9C5D1C0045262EA5E7FA782ED42568C6B7E31019FFFABAEFB79D327A4A7ACBD4D547ACB2DC9CD0403";
const PRIV_EXP_1024: &str = "7172A188DBAD977FE680BE3EC9E0E4E33A4D385208F0383EB02CE3DAF33CD520332DF362BA2588B58292710AC9D2882C4F329DF0C11DD66944FF9B21F98A031ED27C19FE2BCF8A09AD3E254A0FD7AB89E0D1E756BCF37ED24D42D1977EA7C1C78ABF4D13F752AE48B426A2DC98C5D13B2313609FAA6441E835DC61D17A01D1A9";

/// Public exponent (standard: 65537 = 0x10001)
const PUB_EXP: u64 = 65537;

/// Generate a license key for the given name
pub fn generate_license(license_name: &str) -> Result<String> {
    let mut data = Vec::new();

    // Random ID
    data.push(generate_random_string(32));

    // License type
    data.push("license".to_string());

    // License holder name
    data.push(license_name.to_string());

    // Expiry timestamp (2099-12-31)
    data.push("4102415999000".to_string());

    // License count
    data.push("1".to_string());

    // License edition
    data.push("full".to_string());

    // Sign with SHA256+RSA2048
    let key_2048 = create_rsa_key(MODULUS_2048, PRIV_EXP_2048)?;
    let signature_2048 = sign_data_sha256(&data, &key_2048)?;
    data.push(signature_2048);

    // Sign with SHA1+RSA1024
    let key_1024 = create_rsa_key(MODULUS_1024, PRIV_EXP_1024)?;
    let signature_1024 = sign_data_sha1(&data, &key_1024)?;
    data.push(signature_1024);

    encode_data(&data)
}

/// Generate activation response from an activation request
pub fn generate_activation(activation_request: &str) -> Result<String> {
    let request = decode_activation_request(activation_request)?;

    if request.len() < 4 {
        anyhow::bail!(
            "Invalid activation request format: expected at least 4 parts, got {}",
            request.len()
        );
    }

    let mut data = Vec::new();

    // Random salt
    data.push("0.4315672535134567".to_string());

    // Request ID (from request)
    data.push(request[0].clone());

    // Response type
    data.push("activation".to_string());

    // License ID (from request)
    data.push(request[1].clone());

    // Activation success
    data.push("True".to_string());

    // Empty field
    data.push(String::new());

    // Hardware ID and machine info (from request)
    data.push(request[2].clone());
    if request.len() > 3 {
        data.push(request[3].clone());
    }

    // Sign with SHA256+RSA2048
    let key_2048 = create_rsa_key(MODULUS_2048, PRIV_EXP_2048)?;
    let signature_2048 = sign_data_sha256(&data, &key_2048)?;
    data.push(signature_2048);

    // Sign with SHA1+RSA1024
    let key_1024 = create_rsa_key(MODULUS_1024, PRIV_EXP_1024)?;
    let signature_1024 = sign_data_sha1(&data, &key_1024)?;
    data.push(signature_1024);

    encode_data(&data)
}

/// Create RSA private key from hex-encoded modulus and private exponent
fn create_rsa_key(modulus_hex: &str, priv_exp_hex: &str) -> Result<RsaPrivateKey> {
    let n = BigUint::parse_bytes(modulus_hex.as_bytes(), 16).context("Failed to parse modulus")?;
    let d = BigUint::parse_bytes(priv_exp_hex.as_bytes(), 16)
        .context("Failed to parse private exponent")?;
    let e = BigUint::from(PUB_EXP);

    // Create minimal RSA key (without p, q, etc.)
    // This is sufficient for signing operations
    RsaPrivateKey::from_components(n, e, d, vec![]).context("Failed to create RSA key")
}

/// Sign data with SHA256 + RSA PKCS#1 v1.5
fn sign_data_sha256(data: &[String], key: &RsaPrivateKey) -> Result<String> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    // Build signature input (null-terminated strings)
    let mut signature_bytes = Vec::new();
    for item in data {
        signature_bytes.extend_from_slice(item.as_bytes());
        signature_bytes.push(0);
    }

    let signing_key = SigningKey::<Sha256>::new(key.clone());
    let mut rng = rand::thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, &signature_bytes);

    Ok(BASE64.encode(signature.to_bytes()))
}

/// Sign data with SHA1 + RSA PKCS#1 v1.5
fn sign_data_sha1(data: &[String], key: &RsaPrivateKey) -> Result<String> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    // Build signature input (null-terminated strings)
    let mut signature_bytes = Vec::new();
    for item in data {
        signature_bytes.extend_from_slice(item.as_bytes());
        signature_bytes.push(0);
    }

    let signing_key = SigningKey::<Sha1>::new(key.clone());
    let mut rng = rand::thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, &signature_bytes);

    Ok(BASE64.encode(signature.to_bytes()))
}

/// Decode an activation request from Base64
fn decode_activation_request(request: &str) -> Result<Vec<String>> {
    let decoded = BASE64
        .decode(request.trim())
        .context("Failed to decode Base64")?;

    let decrypted = crypto::decrypt(&decoded)?;

    // Split by null bytes
    let parts: Vec<String> = decrypted
        .split(|&b| b == 0)
        .map(|bytes| String::from_utf8_lossy(bytes).to_string())
        .collect();

    Ok(parts)
}

/// Encode data list to Base64 (null-separated, DES encrypted)
fn encode_data(data: &[String]) -> Result<String> {
    let mut bytes = Vec::new();

    for (i, item) in data.iter().enumerate() {
        bytes.extend_from_slice(item.as_bytes());
        if i < data.len() - 1 {
            bytes.push(0); // Null separator
        }
    }

    let encrypted = crypto::encrypt(&bytes)?;
    Ok(BASE64.encode(&encrypted))
}

/// Generate a random alphanumeric string
fn generate_random_string(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    let mut rng = rand::thread_rng();

    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn test_create_keys() {
        let key_2048 = create_rsa_key(MODULUS_2048, PRIV_EXP_2048).unwrap();
        assert_eq!(key_2048.n().bits(), 2048);

        let key_1024 = create_rsa_key(MODULUS_1024, PRIV_EXP_1024).unwrap();
        assert_eq!(key_1024.n().bits(), 1024);
    }

    #[test]
    fn test_generate_license() {
        let license = generate_license("Test User").unwrap();
        assert!(!license.is_empty());
        // Should be valid Base64
        assert!(BASE64.decode(&license).is_ok());
    }

    #[test]
    fn test_random_string() {
        let s = generate_random_string(32);
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
