use hmac::{
    digest::{generic_array::GenericArray, BlockInput, FixedOutput, Reset, Update},
    Hmac, Mac, NewMac,
};

/// Internal implementation of `HMAC_DRBG` as described in NIST SP800-90A:
/// <https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final>
///
/// This is a HMAC-based deterministic random bit generator used internally
/// to compute a deterministic ECDSA ephemeral scalar `k`.
pub struct HmacDrbg<D>
where
    D: BlockInput + FixedOutput + Clone + Default + Reset + Update,
{
    /// HMAC key `K` (see RFC 6979 Section 3.2.c)
    k: Hmac<D>,

    /// Chaining value `V` (see RFC 6979 Section 3.2.c)
    v: GenericArray<u8, D::OutputSize>,
}

impl<D> HmacDrbg<D>
where
    D: BlockInput + FixedOutput + Clone + Default + Reset + Update,
{
    /// Initialize `HMAC_DRBG`
    pub fn new(entropy_input: &[u8], nonce: &[u8], additional_data: &[u8]) -> Self {
        let mut k = Hmac::new(&Default::default());
        let mut v = GenericArray::default();

        for b in &mut v {
            *b = 0x01;
        }

        for i in 0..=1 {
            k.update(&v);
            k.update(&[i]);
            k.update(entropy_input);
            k.update(nonce);
            k.update(additional_data);
            k = Hmac::new_varkey(&k.finalize().into_bytes()).unwrap();

            // Steps 3.2.e,g: v = HMAC_k(v)
            k.update(&v);
            v = k.finalize_reset().into_bytes();
        }

        Self { k, v }
    }

    /// Get the next `HMAC_DRBG` output
    pub fn generate_into(&mut self, out: &mut [u8]) {
        for out_chunk in out.chunks_mut(self.v.len()) {
            self.k.update(&self.v);
            self.v = self.k.finalize_reset().into_bytes();
            out_chunk.copy_from_slice(&self.v[..out_chunk.len()]);
        }

        self.k.update(&self.v);
        self.k.update(&[0x00]);
        self.k = Hmac::new_varkey(&self.k.finalize_reset().into_bytes()).unwrap();
        self.k.update(&self.v);
        self.v = self.k.finalize_reset().into_bytes();
    }
}
