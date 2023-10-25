// use hex::encode;
pub type B96 = [u8; 12];
pub type B128 = [u8; 16];
pub type B256 = [u8; 32];

// pub fn b128_to_u128(v: B128) -> u128 {
//     let he = encode(v);
//     he.parse::<u128>().unwrap()
// }

// #[cfg(test)]
// mod aescbcconfig_tests {
//     use crate::aescbc::tp::b128_to_u128;
//     use k9::assert_equal;

//     #[test]
//     pub fn test_b128_to_u128() {
//         let input = [0xffu8; 16];
//         let result = b128_to_u128(input);
//         assert_equal!(result, 0xffffffffu128);
//     }
// }
