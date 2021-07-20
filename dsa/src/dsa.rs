use core::cmp::Ordering::{self, Equal, Greater, Less};
use num_bigint::algorithms;
use num_bigint::{BigUint, RandPrime};
use num_traits::{FromPrimitive, One};
use rand::prelude::*;
use rand::Rng;

use crate::errors::{Error, Result};
use num_bigint::algorithms::{__add2, __sub2rev, add2, sub2, sub2rev};
use num_bigint::algorithms::{mac_with_carry, mul3, scalar_mul};

/// This program implements the DSA algorithm defined in FIPS 186-3.
///
/// The parameter represents the parameter of the key.
/// The bit length of Q must be a multiple of 8.
struct Parameters {
    P: BigUint,
    Q: BigUint,
    G: BigUint,
}

/// PublicKey represents a DSA public key.
struct PublicKey {
    P: BigUint,
    Q: BigUint,
    G: BigUint,
    Y: BigUint,
}

/// PrivateKey represents a DSA private key.
struct PrivateKey {
    P: BigUint,
    Q: BigUint,
    G: BigUint,
    Y: BigUint,
    X: BigUint,
}

const L1024N160: i8 = 0;
const L2048N224: i8 = 1;
const L2048N256: i8 = 2;
const L3072N256: i8 = 3;

/// numMRTests is the largest recommendation number selected from Table C.1 of FIPS 186-3.
/// It is the quantity used to perform the Miller-Rabin prime number test.
const numTests: i8 = 64;

fn GenerateParameters<L, N>(params: &mut Parameters, rand: Rng, sizes: i8) -> Result<Vec<u8>> {
    let mut L;
    let mut N;
    match sizes {
        L1024N160 => {
            let L = 1024;
            let N = 160;
        }

        L2048N224 => {
            let L = 2048;
            let N = 224;
        }

        L2048N256 => {
            let L = 2048;
            let N = 256;
        }

        L2048N256 => {
            let L = 3072;
            let N = 256;
        }

        _ => {
            return Err(Error::EncodeError {
                reason: "dsa: invalid ParameterSizes".into(),
            })
        }
    }

    let mut qBytes = vec![0u8; N / 8];
    let mut pBytes = vec![0u8; L / 8];

    let mut q: BigUint;
    let mut p: BigUint;
    let mut rem: BigUint;
    let mut one = BigUint::one();

    'GeneratePrimes: loop {
        rand.read(&mut qBytes)?;

        qBytes[qBytes.len() - 1] |= 1;
        qBytes[0] = 0x80;


        if !q.probablyprime(numTests) {

            continue;
        }

        for i in 0..4 * L {
            rand.read(&mut pBytes)?;

            pBytes[pBytes.len() - 1] |= 1;
            pBytes[0] |= 0x80;

            rem.modpow(p, q);
            rem.Sub(rem, one);
            p.Sub(p, rem);

            if p.bits() < L {
                i += 1;
                continue;
            }

            if !probably_prime(q, numTests) {
                i += 1;
                continue;
            }

            params.P = p;
            params.Q = q;
            break 'GeneratePrimes;
        }
    }

    let mut h: BigUint;
    let mut g: BigUint;

    let mut pm1: BigUint;
    pm1.Sub(p, one);
    let mut e: BigUint;
    e.Div(pm1, q);

    loop {
        if g.cmp(one) == 0 {
            h.add(h, one);
            continue;
        }

        params.G = g;
        return None;
    }
}

// GenerateKey generates a public&private key pair.
fn GenerateKey(priva: PrivateKey, rand: Rng) -> Result<Vec<u8>> {
    if priva.P == None || priva.Q == None || priva.G == None {
        return Err(Error::ParametersNotSet);
    }

    let mut x: BigUint;
    let mut xBytes = vec![0u8; priva.Q.bits() / 8];

    loop {
        rand.read(&mut xBytes)?;

        if x.Sign() != 0 && x.cmp(priva.Q) < 0 {
            break;
        }
    }

    priva.X = x;
    priva.Y.exp(priva.G, x, priva.P);
    return None;
}

// fermatInverse calculates the inverse of GP(k).
fn fermatInverse(k: BigUint, P: BigUint) -> BigUint {
    let mut two: BigUint;

    let mut pMinus2: BigUint;
    pMinus2.Sub(P, two);
    return BigUint.exp(k, pMinus2, P);
}

// Find the sign of the BigUint variable.
fn Sign(a: BigUint) -> i8 {
    if a.data == 0 {
        return 0;
    }
    if a.sign < 0 {
        return -1;
    }
    return 1;
}

/// Signature uses the private key priva to sign a hash of any length.
/// It returns the signature as a pair of integers.
/// The security of the private key depends on the entropy of rand.
fn Signature(rand: Rng, priva: PrivateKey, hash: &[i8]) -> (BigUint, BigUint) {

    let mut n = priva.Q.bits();
    if Sign(priva.Q) <= 0
        || Sign(priva.P) <= 0
        || Sign(priva.G) <= 0
        || Sign(priva.X) <= 0
        || n % 8 != 0
    {
        return Err(Error::InvalidPublicKey);
    }

    n >>= 3;

    let mut attwmpts = 10;
    let mut r: BigUint;
    let mut s: BigUint;

    while attwmpts > 0 {
        let mut k: BigUint;
        let mut buf = vec![0u8; n];

        loop {
            rand.read(buf);
            if Sign(k) > 0 && priva.Q.cmp(k) > 0 {
                break;
            }
        }

        let mut kInv = fermatInverse(k, priva.Q);

        r.exp(priva.G, k, priva.P);
        r.modpow(r, priva.Q);

        if Sign(r) == 0 {
            attwmpts -= 1;
            continue;
        }

        let mut z = k.SetBytes(hash);

        s.Mul(priva.X, r);
        s.add(s, z);
        s.modpow(s, priva.Q);
        s.Mul(s, kInv);
        s.modpow(s, priva.Q);

        if Sign(s) != 0 {
            break;
        }
        attwmpts -= 1;
    }

    if attwmpts == 0 {
        return (None, None);
    }

    return (r, s);
}

/// Use the public key to verify the signature in the hash r, s.
/// It reports whether the signature is valid.
fn Verify(publ: PublicKey, hash: &[u8], r: BigUint, s: BigUint) -> bool {
    if Sign(publ.P) == 0 {
        return false;
    }

    if Sign(r) < 1 || r.cmp(publ.Q) >= 0 {
        return false;
    }

    if Sign(s) < 1 || s.cmp(publ.Q) >= 0 {
        return false;
    }

    let mut w: BigUint;
    w.modpow(s, publ.Q);
    if w == None {
        return false;
    }

    let mut n = publ.Q.bits();
    if n % 8 != 0 {
        return false;
    }

    let mut z: BigUint;

    let mut u1: BigUint;
    u1.Mul(z, w);
    u1.modpow(u1, publ.Q);
    let mut u2 = w.Mul(r, w);
    u2.modpow(u2, publ.Q);
    let mut v = u1.Exp(publ.G, u1, publ.P);
    u2.Exp(publ.Y, u2, publ.P);
    v.Mul(v, u2);
    v.modpow(v, publ.P);
    v.modpow(v, publ.Q);

    return v.cmp(r) == 0;
}
