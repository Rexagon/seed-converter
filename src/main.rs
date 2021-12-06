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
        Subcommand::Generate(generate) => {
            let seed = seed_converter::generate_key(generate.ty)
                .context("Failed to generate key")?
                .words
                .join(" ");

            print!("{}", seed);
            Ok(())
        }
        Subcommand::Derive(derive) => {
            let seed = if let Some(seed) = derive.seed {
                seed
            } else {
                let mut seed = String::new();
                std::io::stdin()
                    .read_to_string(&mut seed)
                    .context("Failed to read seed phrase from stdin")?;
                seed
            };

            let path = if let Some(path) = &derive.path {
                path.as_str()
            } else {
                "m/44'/396'/0'/0/0"
            };

            let keys = seed_converter::derive_from_phrase(&seed, derive.ty, path)
                .context("Failed to derive keys")?;

            print!(
                "{{\n  \"public\": \"{}\",\n  \"secret\": \"{}\"\n}}",
                hex::encode(keys.public.as_bytes()),
                hex::encode(keys.secret.as_bytes())
            );
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
}
