use std::convert::TryInto;

use anyhow::Error;
use bip39::{Language, Seed};
use tiny_hderive::bip32::ExtendedPrivKey;

pub fn derive_master_key(phrase: &str) -> anyhow::Result<[u8; 64]> {
    let cnt = phrase.split_whitespace().count();
    anyhow::ensure!(cnt == 12, "Provided {} words instead of 12", cnt);
    let mnemonic = bip39::Mnemonic::from_phrase(phrase, Language::English)?;
    let hd = Seed::new(&mnemonic, "");
    Ok(hd.as_bytes().try_into().expect("Must be valid"))
}

pub fn derive_from_phrase(phrase: &str, path: &str) -> Result<ed25519_dalek::Keypair, Error> {
    let mnemonic = bip39::Mnemonic::from_phrase(phrase, Language::English)?;
    let hd = Seed::new(&mnemonic, "");
    let seed_bytes = hd.as_bytes();

    let derived =
        ExtendedPrivKey::derive(seed_bytes, path).map_err(|e| Error::msg(format!("{:#?}", e)))?;

    ed25519_keys_from_secret_bytes(&derived.secret())
}

pub fn generate_words(entropy: [u8; 16]) -> Vec<String> {
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy, Language::English)
        .expect("Must be valid")
        .phrase()
        .to_string();
    mnemonic.split_whitespace().map(|x| x.to_string()).collect()
}

fn ed25519_keys_from_secret_bytes(bytes: &[u8]) -> Result<ed25519_dalek::Keypair, Error> {
    let secret = ed25519_dalek::SecretKey::from_bytes(bytes).map_err(|e| {
        Error::msg(format!(
            "failed to import ton secret key. {}",
            e.to_string()
        ))
    })?;

    let public = ed25519_dalek::PublicKey::from(&secret);

    Ok(ed25519_dalek::Keypair { secret, public })
}
