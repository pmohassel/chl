use core::ops::Mul;
use miracl_core::bls12381::big::{BIG, MODBYTES};
use miracl_core::bls12381::dbig::DBIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::fp12::FP12;
use miracl_core::bls12381::{big, ecp, pair, rom};
use miracl_core::hmac;
use miracl_core::rand::RAND;

pub struct G1Element(ECP);

#[derive(Clone)]
pub struct G2Element(ECP2);

pub struct GTElement(FP12);

#[derive(Copy, Clone)]
pub struct Scalar(BIG);

const GTS: usize = big::MODBYTES * 12; //number of bytes to represent target group elements
const G1S: usize = 58; //number of bytes to represent G1 elements
const G2S: usize = 58; //number of bytes to represent G2 elements

impl G1Element {
    pub fn generator() -> Self {
        Self(ECP::generator())
    }

    pub fn hash_to_curve(input: &[u8]) -> Self {
        Self(ECP::mapit(input))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: [u8; G1S] = [0; G1S];
        self.0.tobytes(&mut bytes, true);
        bytes.to_vec()
    }
}

impl G2Element {
    pub fn generator() -> Self {
        Self(ECP2::generator())
    }

    pub fn hash_to_curve(input: &[u8]) -> Self {
        Self(ECP2::mapit(input))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: [u8; G2S] = [0; G2S];
        self.0.tobytes(&mut bytes, true);
        bytes.to_vec()
    }
}

impl GTElement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: [u8; GTS] = [0; GTS];
        let mut x = self.0;
        x.tobytes(&mut bytes);
        bytes.to_vec()
    }
}

impl Scalar {
    pub(crate) const NUM_BYTES: usize = MODBYTES;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: [u8; Self::NUM_BYTES] = [0; Self::NUM_BYTES];
        let mut x = self.0;
        x.tobytes(&mut bytes);
        bytes.to_vec()
    }

    pub fn from_bytes_random(input: &[u8]) -> Self {
        Scalar::random(input)
    }
}

impl Mul<G1Element> for Scalar {
    type Output = G1Element;

    fn mul(self, e: G1Element) -> G1Element {
        G1Element(pair::g1mul(&e.0, &self.0))
    }
}

impl Mul<G2Element> for Scalar {
    type Output = G2Element;

    fn mul(self, e: G2Element) -> G2Element {
        G2Element(pair::g2mul(&e.0, &self.0))
    }
}

impl PartialEq for G2Element {
    fn eq(&self, other: &Self) -> bool {
        let mut x = self.0.clone();
        let mut y = other.0.clone();
        x.equals(&mut y)
    }
}

pub fn pair(g1: &G1Element, g2: &G2Element) -> GTElement {
    let mut tmp: [FP12; 65] = pair::initmp();
    pair::another(&mut tmp, &g2.0, &g1.0);
    let alpha2 = pair::miller(&mut tmp);
    GTElement(pair::fexp(&alpha2))
}

//TODO: this should be properly seeded
// this code uses HKDF to generate a random scalar using a seed ikm
// adapted from the library itself
impl Scalar {
    pub fn random(seed: &[u8]) -> Self {
        let mut ikm: [u8; 32] = [0; 32];
        let mut rng = RAND::new();
        rng.seed(seed.len(), seed);

        for x in ikm.iter_mut() {
            *x = rng.getbyte();
        }

        let r = BIG::new_ints(&rom::CURVE_ORDER);
        let el = ceil(3 * ceil(r.nbits(), 8), 2);

        let salt = String::from("BLS-IBE-KEYGEN-SALT-");
        let info = String::from("");

        let mut prk: [u8; 64] = [0; 64];
        let mut okm: [u8; 128] = [0; 128];

        let hlen = ecp::HASH_TYPE;

        hmac::hkdf_extract(hmac::MC_SHA2, hlen, &mut prk, Some(&salt.as_bytes()), &ikm);
        hmac::hkdf_expand(
            hmac::MC_SHA2,
            hlen,
            &mut okm,
            el,
            &prk[0..hlen],
            &info.as_bytes(),
        );

        let mut dx = DBIG::frombytes(&okm[0..el]);
        Self(dx.dmod(&r))
    }
}

// helper function used by randomscalar
fn ceil(a: usize, b: usize) -> usize {
    (a - 1) / b + 1
}
