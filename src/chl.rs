use crate::ibe;
use rand_core::{CryptoRng, RngCore};

type PublicParameters = ibe::PublicParameters;
type SecretParameters = ibe::MasterSecret;
type PasswordFile = (ibe::Key, Vec<u8>);
type LoginMessage = ibe::Ciphertext;

/// Security parameter
static LAMBDA: usize = 32;

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (PublicParameters, SecretParameters) {
    ibe::setup(rng)
}

pub fn register(sk: SecretParameters, uid: &[u8], password: &[u8]) -> PasswordFile {
    let (s, t) = compute_s_and_t(uid, password);
    let f_t = ibe::random_oracle(&t, LAMBDA);
    (ibe::keygen(sk, &s), f_t)
}

pub fn client_login<R: RngCore + CryptoRng>(
    pp: &PublicParameters,
    ssid: &[u8],
    tok: &[u8],
    uid: &[u8],
    password: &[u8],
    rng: &mut R,
) -> LoginMessage {
    let (s, t) = compute_s_and_t(uid, password);
    ibe::encrypt(pp, &s, &[&t, ssid, tok].concat(), rng)
}

pub fn server_login(
    pp: &PublicParameters,
    ssid: &[u8],
    password_file: &PasswordFile,
    login_message: &LoginMessage,
) -> Result<Vec<u8>, String> {
    let (gamma_1, gamma_2) = password_file;
    let result = ibe::decrypt(pp, &gamma_1, login_message)?;

    if result.len() < LAMBDA + ssid.len() {
        return Err("Invalid ssid, too short".to_string());
    }

    let t = &result[..LAMBDA];
    let ssid_prime = &result[LAMBDA..LAMBDA + ssid.len()];
    let tok = &result[LAMBDA + ssid.len()..];

    if ibe::random_oracle(&t, LAMBDA) != gamma_2.clone() || ssid != ssid_prime {
        return Err("Unsuccessful login".to_string());
    }

    Ok(tok.to_vec())
}

// Helper functions

fn compute_s_and_t(uid: &[u8], password: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let s_and_t = ibe::random_oracle(&[uid, password].concat(), 2 * LAMBDA);
    (s_and_t[..LAMBDA].to_vec(), s_and_t[LAMBDA..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_chl_basic() {
        let mut rng = OsRng;
        let (pp, sk) = setup(&mut rng);
        let password_file = register(sk, b"uid1", b"password1");
        let alpha = client_login(&pp, b"ssid1", b"tok1", b"uid1", b"password1", &mut rng);
        let result = server_login(&pp, b"ssid1", &password_file, &alpha);

        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), b"tok1");
    }
}
