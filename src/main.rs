#![feature(slice_as_array)]

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    process,
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
use tempfile::NamedTempFile;

const MIN_PASS_LEN: usize = 8;

#[derive(Serialize, Deserialize)]
struct Vault {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    cert: [u8; 32],
}

impl Vault {
    pub fn new(data: &str, pass: &str) -> anyhow::Result<Self> {
        let key = derive_key(pass)?;
        let (ciphertext, nonce) = encrypt(data.as_bytes(), &key)?;
        let cert = hash(data.as_bytes())?;
        Ok(Self {
            ciphertext,
            nonce,
            cert,
        })
    }

    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = fs::read(path)?;
        serde_json::from_slice(&content).with_context(|| "Failed to deserialize file JSON")
    }

    pub fn read(&self, pass: &str) -> anyhow::Result<String> {
        let key = derive_key(pass)?;
        let plaintext = decrypt(&key, &self.nonce, &self.ciphertext)?;
        if !validate_cert(&self.cert, &plaintext) {
            bail!("cert did not match the plaintext");
        }
        String::from_utf8(plaintext)
            .with_context(|| "Failed to convert plaintext into UTF-8 string")
    }

    pub fn write(&self, path: &str, overwrite: bool) -> anyhow::Result<()> {
        OpenOptions::new()
            .create_new(!overwrite)
            .truncate(overwrite)
            .write(true)
            .open(path)
            .with_context(|| "Failed to create file")?
            .write_all(&serde_json::to_vec(self)?)
            .with_context(|| "Failed to write vault to file")
    }
}

/// A tool for managing vaults - arbitrary pieces of data protected by passphrases.
#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Edit the data inside a vault.
    #[command(arg_required_else_help(true))]
    Edit {
        /// Must exist.
        path: String,
        #[arg(short, long)]
        pass: Option<String>,
    },
    /// Initialize a new vault.
    #[command(arg_required_else_help(true))]
    Init {
        /// Cannot exist.
        path: String,
        #[arg(short, long)]
        pass: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command {
        Command::Init { path, pass } => {
            let pass = get_pass(pass)?;
            let data = edit_in_file(None)?;
            Vault::new(&data, &pass)?.write(&path, /* overwrite= */ false)?;
        }
        Command::Edit { path, pass } => {
            let vault = Vault::from_file(&path)?;
            let pass = get_pass(pass)?;
            let init = vault.read(&pass)?;
            let data = edit_in_file(Some(&init))?;
            Vault::new(&data, &pass)?.write(&path, /* overwrite= */ true)?;
        }
    }

    Ok(())
}

fn edit_in_file(init: Option<&str>) -> anyhow::Result<String> {
    let editor = env::var("EDITOR").with_context(|| "Failed to get the `EDITOR` env var")?;
    let mut file = NamedTempFile::new().with_context(|| "Failed to create a temporary file")?;
    file.write_all(init.unwrap_or("").as_bytes())
        .with_context(|| "Failed to write initial content to the temporary file")?;
    let path = file
        .path()
        .to_str()
        .ok_or_else(|| anyhow!("Failed to get temporary file path"))?;
    let status = process::Command::new(&editor)
        .arg(path)
        .status()
        .with_context(|| "Failed to run editor")?;
    if !status.success() {
        bail!("Editor returned with an error status");
    }
    fs::read_to_string(path).with_context(|| "Failed to read file content after edited")
}

fn encrypt(data: &[u8], key: &[u8; 32]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = Aes256Gcm::new(key.into())
        .encrypt(&nonce, data)
        .map_err(|_| anyhow!("Failed to encrypt plaintext"))?;
    Ok((ciphertext, nonce.as_slice().to_vec()))
}

fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce);
    Aes256Gcm::new(key.into())
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Failed to decrypt ciphertext, probably incorrect pass"))
}

fn get_pass(pass: Option<String>) -> anyhow::Result<String> {
    let pass = match pass {
        Some(pass) => pass,
        None => prompt_pass()?,
    };
    if pass.len() < MIN_PASS_LEN {
        bail!("pass too short");
    }
    Ok(pass)
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
