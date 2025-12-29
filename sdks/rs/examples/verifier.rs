use std::env;

use marlin::attestation::{AttestationExpectations, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <url>", args[0]);
        std::process::exit(1);
    }

    let url = &args[1];
    let response = reqwest::blocking::get(url)?.bytes()?;

    let decoded = verify(
        &response,
        AttestationExpectations {
            ..Default::default()
        },
    )?;

    println!("{:?}", decoded);

    Ok(())
}
