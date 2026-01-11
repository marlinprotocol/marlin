use clap::Parser;
use secp256k1::{generate_keypair, rand};
use std::{error::Error, fs::File, io::Write};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// path to private key file
    #[arg(short, long)]
    secret: String,

    /// path to public key file
    #[arg(short, long)]
    public: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    println!("private key: {}, public key: {}", cli.secret, cli.public);

    let (secret, public) = generate_keypair(&mut rand::rng());

    let mut file = File::create(cli.secret)?;
    file.write_all(&secret.secret_bytes())?;

    let mut file = File::create(cli.public)?;
    file.write_all(&public.serialize_uncompressed()[1..])?;

    println!("Generation successful!");

    Ok(())
}
