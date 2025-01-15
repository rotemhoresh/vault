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

    pub fn open(&self, pass: &str) -> anyhow::Result<String> {
        let key = derive_key(pass)?;
        let plaintext = decrypt(&key, &self.nonce, &self.ciphertext)?;
        if !validate_cert(&self.cert, &plaintext) {
            bail!("cert did not match the plaintext");
        }
        String::from_utf8(plaintext)
            .with_context(|| "Failed to convert plaintext into UTF-8 string")
    }

    pub fn write(&self, path: &str) -> anyhow::Result<()> {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .with_context(|| "Failed to create file")?
            .write_all(&serde_json::to_vec(self)?)
            .with_context(|| "Failed to write vault to file")
    }
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
            let vault = Vault::from_file(&path)?;
            let pass = get_pass(pass)?;
            println!("{}", vault.open(&pass)?);
        }
        Command::Init { path } => {
            let pass = get_pass(None)?;
            let data = prompt_data()?;
            Vault::new(&data, &pass)?.write(&path)?;
            println!("success!");
        }
    }

    Ok(())
}

fn encrypt(data: &[u8], key: &[u8; 32]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = Aes256Gcm::new(key.into())
        .encrypt(&nonce, data)
        .map_err(|err| anyhow!("Failed to encrypt plaintext: {}", err))?;
    Ok((ciphertext, nonce.as_slice().to_vec()))
}

fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce);
    Aes256Gcm::new(key.into())
        .decrypt(nonce, ciphertext)
        .map_err(|err| anyhow!("Failed to decrypt ciphertext: {}", err))
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

fn prompt_data() -> anyhow::Result<String> {
    let mut data = String::new();
    print!("enter data: ");
    io::stdout()
        .flush()
        .with_context(|| "Failed to flush stdout")?;
    io::stdin()
        .read_line(&mut data)
        .with_context(|| "Failed to read from stdin")?;
    Ok(data)
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
