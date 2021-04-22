//! Support for computing deterministic DSA or ECDSA ephemeral scalar (`k`).
//!
//! Implementation of the algorithm described in RFC 6979 (Section 3.2):
//! <https://tools.ietf.org/html/rfc6979#section-3>
//!
//! The generics `I`, `O`, and `T` are merely so checks can be optimized away if all are
//! fixed-size arrays.

pub use hmac;

use hmac::digest::{BlockInput, FixedOutput, Reset, Update};

pub mod hmac_drbg;

pub struct KGenerator<D, I>
where
    D: BlockInput + FixedOutput + Clone + Default + Reset + Update,
    I: AsRef<[u8]>,
{
    modulus: I,
    rng: hmac_drbg::HmacDrbg<D>,
}

impl<D, I> KGenerator<D, I>
where
    D: BlockInput + FixedOutput + Clone + Default + Reset + Update,
    I: AsRef<[u8]>,
{
    /// The `secret` is the secret part of the DSA private key. `digest` is the hash of the
    /// message being signed, in general using the same hash algorithm as the one passed to
    /// `KGenerator` as a generic parameter.
    ///
    /// Both should have been truncated to the same number of bits as needed to represent the
    /// modulus, interpreted as a big-endian number, reduced to being below the modulus by
    /// subtracting the modulus if it is larger than the modulus, and then encoding as a big
    /// endian number, padded with leading zero bytes to the same length as the modulus.
    /// See RFC6979 for details.
    ///
    /// The modulus must be in big endian format with no padding (i.e. first byte must not be 0).
    ///
    /// This function will panic if these requirements are not met.
    pub fn new<T: AsRef<[u8]>>(modulus: I, secret: T, digest: T, additional_data: &[u8]) -> Self {
        let rng = {
            let modulus = modulus.as_ref();
            let secret = secret.as_ref();
            let digest = digest.as_ref();
            assert!(modulus.len() > 0 && modulus[0] != 0);
            assert!(secret.len() == modulus.len() && secret < modulus);
            assert!(digest.len() == modulus.len() && digest < modulus);
            hmac_drbg::HmacDrbg::new(secret, digest, additional_data)
        };

        Self { modulus, rng }
    }

    /// Generate the next number smaller than `modulus` into the passed buffer.
    /// The buffer must be of the same length as the modulus, or the function will panic.
    pub fn generate_into<O: AsMut<[u8]>>(&mut self, mut out: O) {
        let modulus = self.modulus.as_ref();
        let out = out.as_mut();
        assert!(out.len() == modulus.len());

        // Many or all reasonable use cases will use all available bits in the modulus and thus
        // have shift equal to 0. But for classic DSA people generate their own domain params,
        // and even among older elliptic curves likely to be used with EC-DSA there are oddballs
        // like P-521.
        let shift = modulus[0].leading_zeros();
        loop {
            self.rng.generate_into(out);

            if shift != 0 {
                // shift entire buffer right by `shift` bits
                let mut next_hi = 0;
                for b in out.iter_mut() {
                    let hi = next_hi;
                    let lo = b.wrapping_shr(shift);
                    next_hi = b.wrapping_shl(8 - shift);
                    *b = hi | lo;
                }
            }

            if &*out < modulus {
                break;
            }
        }
    }
}
