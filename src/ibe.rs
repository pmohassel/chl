use crate::pairings::*;

use miracl_core::sha3::{HASH256, SHA3};
use rand_core::{CryptoRng, RngCore};

pub(crate) type PublicParameters = (G2Element, G2Element);
pub(crate) type MasterSecret = Scalar;
pub(crate) type Key = G1Element;
pub(crate) type Ciphertext = (G2Element, Vec<u8>, Vec<u8>);

// Random oracle

pub(crate) fn random_oracle(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut sh = SHA3::new(output_len);
    sh.process_array(input);
    let mut digest = vec![0u8; output_len];
    sh.hash(&mut digest);
    digest
}

fn ro1(input: &[u8]) -> G1Element {
    G1Element::hash_to_curve(&random_oracle(input, HASH256))
}

fn ro2_with_pairing(g1: &G1Element, g2: &G2Element) -> Vec<u8> {
    let gt = pair(g1, g2);

    random_oracle(&gt.to_bytes(), HASH256)
}

fn ro3(sigma: &[u8], message: &[u8]) -> Scalar {
    Scalar::from_bytes_random(&random_oracle(
        &[sigma, message].concat(),
        Scalar::NUM_BYTES,
    ))
}

fn ro4(sigma: &[u8], output_len: usize) -> Vec<u8> {
    random_oracle(sigma, output_len)
}

fn xor(v1: &[u8], v2: &[u8]) -> Vec<u8> {
    v1.iter().zip(v2.iter()).map(|(&x1, &x2)| x1 ^ x2).collect()
}

pub(crate) fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (PublicParameters, MasterSecret) {
    let g = G2Element::generator();

    let mut random_bytes = [0u8; HASH256];
    rng.fill_bytes(&mut random_bytes);

    let s = Scalar::random(&random_bytes);
    let h = s * g.clone();
    ((g, h), s)
}

pub(crate) fn keygen(s: MasterSecret, id: &[u8]) -> Key {
    s * ro1(id)
}

#[allow(clippy::many_single_char_names)]
pub(crate) fn encrypt<R: RngCore + CryptoRng>(
    pp: &PublicParameters,
    id: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Ciphertext {
    let mut sigma = [0u8; HASH256];
    rng.fill_bytes(&mut sigma);

    let (p, p_pub) = pp;

    let qid = ro1(id);

    let r = ro3(&sigma, message);

    let u = r * p.clone();
    let v = xor(&sigma, &ro2_with_pairing(&(r * qid), &p_pub));
    let w = xor(&message, &ro4(&sigma, message.len()));

    (u, v, w)
}

#[allow(clippy::many_single_char_names)]
pub(crate) fn decrypt(
    pp: &PublicParameters,
    key: &Key,
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>, String> {
    let (p, _) = pp;
    let (u, v, w) = ciphertext;
    let pair_result = ro2_with_pairing(key, &u);

    let sigma = xor(&v, &pair_result);
    let message = xor(&w, &ro4(&sigma, w.len()));
    let r = ro3(&sigma, &message);

    if u.clone() != r * p.clone() {
        return Err("Invalid ciphertext!".to_string());
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_ibe_basic() {
        let mut rng = OsRng;
        let (pp, msk) = setup(&mut rng);
        let key = keygen(msk, b"id1");

        let ciphertext = encrypt(&pp, b"id1", b"msg1", &mut rng);

        let msg1_decrypted = decrypt(&pp, &key, &ciphertext);
        assert_eq!(msg1_decrypted.is_ok(), true);
        assert_eq!(msg1_decrypted.unwrap(), b"msg1");
    }
}
