use anyhow::{Context, Result};
use argh::FromArgs;
use std::io::Read;

use seed_converter::MnemonicType;

fn main() {
    if let Err(e) = run(argh::from_env()) {
        eprintln!("{:?}", e);
        std::process::exit(1);
    }
}

fn run(app: App) -> Result<()> {
    match app.command {
        Subcommand::Generate(args) => {
            let seed = seed_converter::generate_key(args.ty)
                .context("Failed to generate key")?
                .words
                .join(" ");

            print!("{}", seed);
            Ok(())
        }
        Subcommand::Derive(args) => {
            let seed = if let Some(seed) = args.seed {
                seed
            } else {
                let mut seed = String::new();
                std::io::stdin()
                    .read_to_string(&mut seed)
                    .context("Failed to read seed phrase from stdin")?;
                seed
            };

            let path = if let Some(path) = &args.path {
                path.as_str()
            } else {
                "m/44'/396'/0'/0/0"
            };

            let keys = seed_converter::derive_from_phrase(seed.trim(), args.ty, path)
                .context("Failed to derive keys")?;

            print!("{}", encode_key_pair(keys.secret, keys.public, args.base64));
            Ok(())
        }
        Subcommand::Pubkey(args) => {
            let secret = if let Some(secret) = args.secret {
                secret
            } else {
                let mut secret = String::new();
                std::io::stdin()
                    .read_to_string(&mut secret)
                    .context("Failed to read secret from stdin")?;
                secret
            };

            let secret = match hex::decode(secret.trim()) {
                Ok(bytes) if bytes.len() == 32 => {
                    ed25519_dalek::SecretKey::from_bytes(&bytes).expect("Shouldn't fail")
                }
                _ => match base64::decode(secret.trim()) {
                    Ok(bytes) if bytes.len() == 32 => {
                        ed25519_dalek::SecretKey::from_bytes(&bytes).expect("Shouldn't fail")
                    }
                    _ => return Err(anyhow::anyhow!("Invalid secret key")),
                },
            };

            let public = ed25519_dalek::PublicKey::from(&secret);

            print!("{}", encode_key_pair(secret, public, args.base64));
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, FromArgs)]
#[argh(description = "Simple seed generator/converter")]
struct App {
    #[argh(subcommand)]
    command: Subcommand,
}

#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand)]
enum Subcommand {
    Generate(CmdGenerate),
    Derive(CmdDerive),
    Pubkey(CmdPubkey),
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates new seed
#[argh(subcommand, name = "generate")]
struct CmdGenerate {
    /// mnemonic type
    #[argh(option, long = "type", short = 't', default = "MnemonicType::Labs")]
    ty: MnemonicType,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Derives key from seed
#[argh(subcommand, name = "derive")]
struct CmdDerive {
    /// mnemonic type
    #[argh(option, long = "type", short = 't', default = "MnemonicType::Labs")]
    ty: MnemonicType,

    /// seed phrase or empty for input from stdin
    #[argh(positional)]
    seed: Option<String>,

    /// derivation path for bip39 mnemonic
    #[argh(option, short = 'p')]
    path: Option<String>,

    /// encode keys in base64 (hex by default)
    #[argh(option, short = 'b')]
    base64: bool,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Computes public key from secret key
#[argh(subcommand, name = "pubkey")]
struct CmdPubkey {
    /// secret key in hex or empty for input from stdin
    #[argh(positional)]
    secret: Option<String>,

    /// encode keys in base64 (hex by default)
    #[argh(option, short = 'b')]
    base64: bool,
}

fn encode_key_pair(
    secret: ed25519_dalek::SecretKey,
    public: ed25519_dalek::PublicKey,
    base64: bool,
) -> String {
    let encode = |bytes: &[u8; 32]| -> String {
        if base64 {
            base64::encode(bytes)
        } else {
            hex::encode(bytes)
        }
    };

    format!(
        "{{\n  \"public\": \"{}\",\n  \"secret\": \"{}\"\n}}",
        encode(public.as_bytes()),
        encode(secret.as_bytes()),
    )
}
