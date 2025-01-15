#![feature(slice_as_array)]

use std::{
    fmt::Debug,
    fs::{self, OpenOptions},
    io::{self, Write},
};

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use anyhow::{Context, anyhow, bail};
use argon2::Argon2;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MIN_PASS_LEN: usize = 8;

#[derive(Serialize, Deserialize)]
struct Vault {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    cert: [u8; 32],
}

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(arg_required_else_help(true))]
    Open {
        path: String,
        #[arg(short, long)]
        pass: Option<String>,
    },
    #[command(arg_required_else_help(true))]
    Init { path: String },
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command {
        Command::Open { path, pass } => {
            let content = fs::read(path)?;
            let vault: Vault = serde_json::from_slice(&content)?;
            let pass = match pass {
                Some(pass) => pass,
                None => prompt_pass()?,
            };
            if pass.len() < MIN_PASS_LEN {
                bail!("pass too short");
            }
            let key = derive_key(&pass)?;
            let cipher = Aes256Gcm::new(&key.into());
            let nonce = Nonce::from_slice(&vault.nonce);
            let plaintext = cipher
                .decrypt(nonce, vault.ciphertext.as_slice())
                .map_err(|err| anyhow!("Failed to decrypt ciphertext: {}", err))?;
            if !validate_cert(&vault.cert, &plaintext) {
                bail!("cert did not match the plaintext");
            }
            let string = String::from_utf8(plaintext)
                .with_context(|| "Failed to convert plaintext into UTF-8 string")?;
            println!("{}", string);
        }
        Command::Init { path } => {
            let pass = prompt_pass()?;
            if pass.len() < MIN_PASS_LEN {
                bail!("pass too short");
            }
            let mut data = String::new();
            print!("enter data: ");
            io::stdout()
                .flush()
                .with_context(|| "Failed to flush stdout")?;
            io::stdin()
                .read_line(&mut data)
                .with_context(|| "Failed to read from stdin")?;
            let key = derive_key(&pass)?;
            let cipher = Aes256Gcm::new(&key.into());
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ciphertext = cipher
                .encrypt(&nonce, data.as_bytes())
                .map_err(|_| anyhow!("Failed to encrypt plaintext"))?;
            let cert = hash(data.as_bytes())?;
            let vault = Vault {
                ciphertext,
                nonce: nonce.as_slice().to_vec(),
                cert,
            };
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .with_context(|| "Failed to create file")?; // TODO: better message
            file.write_all(&serde_json::to_vec(&vault)?)?;
        }
    }

    Ok(())
}

#[inline]
fn prompt_pass() -> anyhow::Result<String> {
    rpassword::prompt_password("enter pass: ").with_context(|| "Failed to read pass from stdin")
}

fn derive_key(pass: &str) -> anyhow::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let salt = [0u8; 8];
    Argon2::default()
        .hash_password_into(pass.as_bytes(), &salt, &mut key)
        .map_err(|_| anyhow!("Failed to derive a key from pass"))?;
    Ok(key)
}

/// Returns true if `cert` is valid for the given `data`.
#[inline]
fn validate_cert(cert: &[u8; 32], data: &[u8]) -> bool {
    hash(data).is_ok_and(|ref hash| hash == cert)
}

fn hash(data: &[u8]) -> anyhow::Result<[u8; 32]> {
    Sha256::new()
        .chain_update(data)
        .finalize()
        .as_array()
        .map(|h| h.to_owned())
        .ok_or_else(|| anyhow!("Failed to hash"))
}
