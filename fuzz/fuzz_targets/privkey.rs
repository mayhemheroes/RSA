#![no_main]
use libfuzzer_sys::fuzz_target;
use rsa::{RsaPrivateKey, BigUint};

fuzz_target!(|input: (&[u8], &[u8], &[u8], Vec<&[u8]>)| {
    let (n_bytes, e_bytes, d_bytes, primes_bytes) = input;
    if n_bytes.len() == 0 || e_bytes.len() == 0 || d_bytes.len() == 0 || primes_bytes.iter().any(|b| b.len() == 0) {
        return
    }
    let n = BigUint::from_bytes_be(n_bytes);
    let e = BigUint::from_bytes_be(e_bytes);
    let d = BigUint::from_bytes_be(d_bytes);
    let primes: Vec<_> = primes_bytes.iter().map(|b| BigUint::from_bytes_be(b)).collect();
    let _ = RsaPrivateKey::from_components(n, e, d, primes);
});