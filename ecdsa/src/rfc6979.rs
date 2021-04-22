//! Support for computing deterministic ECDSA ephemeral scalar (`k`).
//!
//! Implementation of the algorithm described in RFC 6979 (Section 3.2):
//! <https://tools.ietf.org/html/rfc6979#section-3>

use crate::hazmat::FromDigest;
use bitvec::prelude::*;
use elliptic_curve::{
    ff::{Field, PrimeField},
    ops::Invert,
    weierstrass::Curve,
    zeroize::{Zeroize, Zeroizing},
    FieldBytes, NonZeroScalar, ProjectiveArithmetic, Scalar,
};
use signature::digest::{BlockInput, FixedOutput, Reset, Update};

use ::rfc6979::KGenerator;

/// Generate ephemeral scalar `k` from the secret scalar and a digest of the
/// input message.
pub fn generate_k<C, D>(
    secret_scalar: &NonZeroScalar<C>,
    msg_digest: D,
    additional_data: &[u8],
) -> Zeroizing<NonZeroScalar<C>>
where
    C: Curve + ProjectiveArithmetic,
    D: FixedOutput<OutputSize = C::FieldSize> + BlockInput + Clone + Default + Reset + Update,
    Scalar<C>:
        PrimeField<Repr = FieldBytes<C>> + FromDigest<C> + Invert<Output = Scalar<C>> + Zeroize,
{
    let bits_to_bytes = |b: elliptic_curve::ScalarBits<C>| {
        // make byte buffer of the right size
        let mut tmp = FieldBytes::<C>::default();
        // convert bitslice from internal repr based on u32 or u64 to one based on u8
        tmp.as_mut_slice()
            .view_bits_mut::<Lsb0>()
            .clone_from_bitslice(b.as_bitslice());
        // convert to big endian
        tmp.reverse();
        tmp
    };

    // Verify that values roundtrip through bits_to_bytes and from_repr as expected.
    // The from_repr interface does not guarantee big endian interpretation, and if it is not
    // as expected the generated value may not have the required entropy.
    let one = Scalar::<C>::one();
    let one_bytes = bits_to_bytes(one.to_le_bits());
    assert!(
        one_bytes[one_bytes.len() - 1] == 1 && Scalar::<C>::from_repr(one_bytes) == Some(one),
        "curve repr not as expected"
    );

    // Convert inputs to big endian byte representation
    let modulus = bits_to_bytes(Scalar::<C>::char_le_bits());
    let h1 = bits_to_bytes(Scalar::<C>::from_digest(msg_digest).to_le_bits());
    let mut x = bits_to_bytes(secret_scalar.to_le_bits());

    let mut gen = KGenerator::<D, _>::new(&modulus, &x, &h1, additional_data);
    x.zeroize();

    loop {
        // Generate value less than the modulus according to RFC6979
        let mut tmp = FieldBytes::<C>::default();
        gen.generate_into(&mut tmp);

        if let Some(k) = NonZeroScalar::from_repr(tmp) {
            return Zeroizing::new(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::generate_k;
    use elliptic_curve::{dev::NonZeroScalar, ff::PrimeField};
    use hex_literal::hex;
    use sha2::{Digest, Sha256};

    /// Test vector from RFC 6979 Appendix 2.5 (NIST P-256 + SHA-256)
    /// <https://tools.ietf.org/html/rfc6979#appendix-A.2.5>
    #[test]
    fn appendix_2_5_test_vector() {
        let x = NonZeroScalar::from_repr(
            hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").into(),
        )
        .unwrap();

        let digest = Sha256::new().chain("sample");
        let k = generate_k(&x, digest, &[]);

        assert_eq!(
            k.to_repr().as_slice(),
            &hex!("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60")[..]
        );
    }
}
