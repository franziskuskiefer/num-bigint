#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate num_bigint;
use num_bigint::BigUint;

extern crate openssl;
use openssl::bn::BigNum;

fuzz_target!(|data: &[u8]| {
    let len = data.len();
    if len < 2 {
        // Not enough data to fuzz
        return;
    }

    let a_ossl = BigNum::from_slice(&data[0..len/2]).unwrap();
    let b_ossl = BigNum::from_slice(&data[len/2..]).unwrap();
    let c_ossl = &a_ossl * &b_ossl;
    let c_ossl = c_ossl.to_vec();
    
    let a = BigUint::from_bytes_be(&data[0..len/2]);
    let b = BigUint::from_bytes_be(&data[len/2..]);
    let c = &a * &b;
    let c = c.to_bytes_be();

    if c_ossl.len() == 0 {
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], 0);
        return;
    }
    assert_eq!(c_ossl, c);
});
