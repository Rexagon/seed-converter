use std::str::FromStr;

use anyhow::Error;
use ed25519_dalek::Keypair;

pub mod dict;
pub mod labs;
pub mod legacy;
mod utils;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MnemonicType {
    /// Phrase with 24 words, used in Crystal Wallet
    Legacy,
    /// Phrase with 12 words, used everywhere else. The additional parameter is used in
    /// derivation path to create multiple keys from one mnemonic
    Labs,
}

impl FromStr for MnemonicType {
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "legacy" => Ok(Self::Legacy),
            "bip39" | "labs" => Ok(Self::Labs),
            _ => Err(MnemonicError::UnknownType),
        }
    }
}

#[derive(Debug)]
pub struct GeneratedKey {
    pub words: Vec<String>,
    pub account_type: MnemonicType,
}

pub fn derive_from_phrase(
    phrase: &str,
    mnemonic_type: MnemonicType,
    path: &str,
) -> Result<Keypair, Error> {
    match mnemonic_type {
        MnemonicType::Legacy => legacy::derive_from_phrase(phrase),
        MnemonicType::Labs => labs::derive_from_phrase(phrase, path),
    }
}

/// Generates mnemonic and keypair.
pub fn generate_key(account_type: MnemonicType) -> Result<GeneratedKey, Error> {
    Ok(GeneratedKey {
        account_type,
        words: match account_type {
            MnemonicType::Legacy => legacy::generate_words(generate_entropy::<32>()?),
            MnemonicType::Labs => labs::generate_words(generate_entropy::<16>()?),
        },
    })
}

fn generate_entropy<const N: usize>() -> Result<[u8; N], MnemonicError> {
    use ring::rand::SecureRandom;

    let rng = ring::rand::SystemRandom::new();

    let mut entropy = [0; N];
    rng.fill(&mut entropy)
        .map_err(MnemonicError::FailedToGenerateRandomBytes)?;
    Ok(entropy)
}

#[derive(thiserror::Error, Debug)]
pub enum MnemonicError {
    #[error("Unknown mnemonic type (neither `legacy` nor `bip39`)")]
    UnknownType,
    #[error("Failed to generate random bytes")]
    FailedToGenerateRandomBytes(ring::error::Unspecified),
}
