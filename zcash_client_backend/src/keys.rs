//! Helper functions for managing light client key material.

use std::convert::TryInto;

use base58::{FromBase58, ToBase58};
use failure::format_err;
use ring::hmac::{Context, HMAC_SHA512, Key};
use secp256k1::{
    key::{PublicKey, SecretKey},
    Secp256k1,
};
use sha2::{Digest, Sha256};
use zcash_primitives::{
    legacy::TransparentAddress,
    zip32::{ChildIndex, ExtendedSpendingKey},
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// BEGIN : [hdwallet]
// ExtendedPrivKey related code modified from hdwallet @ https://docs.rs/hdwallet/0.2.5/src/hdwallet/extended_key/key_index.rs.html

const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648; // 2 ** 31

/// [hdwallet] Random entropy for extended key, per BIP-32
type ChainCode = Vec<u8>;

/// [hdwallet]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrivKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

/// [hdwallet] KeyIndex indicates the key type and index of a child key.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyIndex {
    /// Normal key, index range is from 0 to 2 ** 31 - 1
    Normal(u32),
    /// Hardened key, index range is from 2 ** 31 to 2 ** 32 - 1
    Hardened(u32),
}

/// [hdwallet]
impl KeyIndex {
    pub fn hardened_from_normalize_index(i: u32) -> Result<KeyIndex, Error> {
        if i < HARDENED_KEY_START_INDEX {
            Ok(KeyIndex::Hardened(HARDENED_KEY_START_INDEX + i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }
    pub fn is_valid(self) -> bool {
        match self {
            KeyIndex::Normal(i) => i < HARDENED_KEY_START_INDEX,
            KeyIndex::Hardened(i) => i >= HARDENED_KEY_START_INDEX,
        }
    }
}
/// [hdwallet]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// Index is out of range
    KeyIndexOutOfRange,
    // /// ChainPathError
    // ChainPath(ChainPathError),
    Secp(secp256k1::Error),
    InvalidSecretKeyWif,
}
/// [hdwallet]
impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Error {
        Error::Secp(err)
    }
}
/// [hdwallet]
impl ExtendedPrivKey {

    /// Generate an ExtendedPrivKey from seed
    pub fn with_seed(seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
        let signature = {
            let signing_key = Key::new(HMAC_SHA512, b"Bitcoin seed");
            let mut h = Context::with_key(&signing_key);
            h.update(&seed);
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(key)?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }

    fn sign_hardended_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        h.update(&[0x00]);
        h.update(&self.private_key[..]);
        h.update(&index.to_be_bytes());
        h.sign()
    }

    fn sign_normal_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.private_key);
        h.update(&public_key.serialize());
        h.update(&index.to_be_bytes());
        h.sign()
    }

    /// Derive a child key from ExtendedPrivKey.
    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<ExtendedPrivKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::KeyIndexOutOfRange);
        }
        let signature = match key_index {
            KeyIndex::Hardened(index) => self.sign_hardended_key(index),
            KeyIndex::Normal(index) => self.sign_normal_key(index),
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let mut private_key = SecretKey::from_slice(key)?;
        private_key.add_assign(&self.private_key[..])?;
        Ok(ExtendedPrivKey {
            private_key,
            chain_code: chain_code.to_vec(),
        })
    }
}
// END : [hdwallet]
////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////
// BEGIN : [wagyu]
// WIF logic modified from: Wagyu @ https://github.com/AleoHQ/wagyu/blob/217c139466a41a3d6e13917621496b7a304bd2dc/zcash/src/private_key.rs

// custom implementation of [wagyu] logic as a trait of SecretKey
pub trait Wifable where Self: Sized {
    fn to_wif(self, compressed: bool) -> String;
    fn from_wif(wif: &str) -> Result<Self, failure::Error>;
}

impl Wifable for SecretKey {
    // modified from [wagyu]
    fn to_wif(self, compressed: bool) -> String {
        let pk_hex = self.to_string();
        let mut secret_key = [0; 32];
        from_hex(&pk_hex, &mut secret_key);

        let mut wif = [0u8; 38];
        wif[0] = 0x80;
        wif[1..33].copy_from_slice(&(secret_key));

        if compressed {
            wif[33] = 0x01;
            let sum = &checksum(&wif[0..34])[0..4];
            wif[34..].copy_from_slice(sum);
            wif.to_base58()
        } else {
            let sum = &checksum(&wif[0..33])[0..4];
            wif[33..37].copy_from_slice(sum);
            wif[..37].to_base58()
        }
    }

    // modified from [wagyu]
    fn from_wif(wif: &str) -> Result<SecretKey, failure::Error> {
        let data = wif.from_base58().unwrap();
        let len = data.len();
        if len != 37 && len != 38 {
            return Err(format_err!("invalid char length: {}", len));
            // return Err(PrivateKeyError::InvalidCharacterLength(len));
        }

        let expected = &data[len - 4..][0..4];
        let checksum = &checksum(&data[0..len - 4])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(format_err!("invalid checksum. Expected: {}  Found: {}", expected, found));
            // return Err(PrivateKeyError::InvalidChecksum(expected, found));
        }
        Ok(SecretKey::from_slice(&data[1..33]).expect("wrong size key"))
    }
}

fn checksum(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(&data)).to_vec()
}

// copied from https://github.com/rust-bitcoin/rust-secp256k1/blob/master/src/lib.rs
/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'...b'F' => b |= c - b'A' + 10,
            b'a'...b'f' => b |= c - b'a' + 10,
            b'0'...b'9' => b |= c - b'0',
            _ => return Err(()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}

// END : [wagyu]
////////////////////////////////////////////////////////////////////////////////////////////////////


/// Derives the ZIP 32 [`ExtendedSpendingKey`] for a given coin type and account from the
/// given seed.
///
/// # Panics
///
/// Panics if `seed` is shorter than 32 bytes.
///
/// # Examples
///
/// ```
/// use zcash_primitives::{constants::testnet::COIN_TYPE};
/// use zcash_client_backend::{keys::spending_key};
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, 0);
/// ```
pub fn spending_key(seed: &[u8], coin_type: u32, account: u32) -> ExtendedSpendingKey {
    if seed.len() < 32 {
        panic!("ZIP 32 seeds MUST be at least 32 bytes");
    }

    ExtendedSpendingKey::from_path(
        &ExtendedSpendingKey::master(&seed),
        &[
            ChildIndex::Hardened(32),
            ChildIndex::Hardened(coin_type),
            ChildIndex::Hardened(account),
        ],
    )
}

pub fn derive_transparent_address_from_secret_key(
    secret_key: secp256k1::key::SecretKey,
) -> TransparentAddress {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &secret_key);
    let mut hash160 = ripemd160::Ripemd160::new();
    hash160.update(Sha256::digest(&pk.serialize()[..].to_vec()));
    TransparentAddress::PublicKey(*hash160.finalize().as_ref())
}

pub fn derive_transparent_address_from_secret_key_wif(
    secret_key_wif: &str,
) -> Result<TransparentAddress, Error> {
    match SecretKey::from_wif(&secret_key_wif) {
        Ok(sk) => Ok(derive_transparent_address_from_secret_key(sk)),
        Err(e) => {
            return Err(Error::InvalidSecretKeyWif);
        },
    }
}

pub fn derive_secret_key_from_seed(
    seed: &[u8],
    coin_type: u32,
    account: u32,
    index: u32,
) -> SecretKey {
    let ext_t_key = ExtendedPrivKey::with_seed(&seed).unwrap();
    let address_sk = ext_t_key
        .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap())
        .unwrap()
        .derive_private_key(
            KeyIndex::hardened_from_normalize_index(coin_type).unwrap(),
        )
        .unwrap()
        .derive_private_key(KeyIndex::hardened_from_normalize_index(account).unwrap())
        .unwrap()
        .derive_private_key(KeyIndex::Normal(0))
        .unwrap()
        .derive_private_key(KeyIndex::Normal(index))
        .unwrap()
        .private_key;
    return address_sk;
}

#[cfg(test)]
mod tests {
    use secp256k1::key::SecretKey;
    use zcash_primitives::consensus::MAIN_NETWORK;

    use crate::encoding::AddressCodec;
    use crate::keys::{derive_secret_key_from_seed, derive_transparent_address_from_secret_key, derive_transparent_address_from_secret_key_wif, ExtendedPrivKey, Wifable};
    use crate::keys::from_hex;

    use super::spending_key;

    #[test]
    #[should_panic]
    fn spending_key_panics_on_short_seed() {
        let _ = spending_key(&[0; 31][..], 0, 0);
    }

    #[test]
    fn sk_to_wif() {
        let seed_hex = "6ef5f84def6f4b9d38f466586a8380a38593bd47c8cda77f091856176da47f26b5bd1c8d097486e5635df5a66e820d28e1d73346f499801c86228d43f390304f";
        let mut seed = [0; 64];
        from_hex(&seed_hex, &mut seed);

        let sk = derive_secret_key_from_seed(&seed, 133, 0, 0);

        assert_eq!(sk.to_wif(true), "L4BvDC33yLjMRxipZvdiUmdYeRfZmR8viziwsVwe72zJdGbiJPv2".to_string());
    }

    #[test]
    fn sk_to_taddr() {
        let seed_hex = "6ef5f84def6f4b9d38f466586a8380a38593bd47c8cda77f091856176da47f26b5bd1c8d097486e5635df5a66e820d28e1d73346f499801c86228d43f390304f";
        let mut seed = [0; 64];
        from_hex(&seed_hex, &mut seed);

        let sk = derive_secret_key_from_seed(&seed, 133, 0, 0);
        let taddr = derive_transparent_address_from_secret_key(sk);

        assert_eq!(taddr.encode(&MAIN_NETWORK), "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }


    #[test]
    fn sk_wif_to_taddr() {
        let sk_wif = "L4BvDC33yLjMRxipZvdiUmdYeRfZmR8viziwsVwe72zJdGbiJPv2";
        let taddr = derive_transparent_address_from_secret_key_wif(sk_wif);

        assert_eq!(taddr.unwrap().encode(&MAIN_NETWORK), "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }
}
