use std::collections::HashMap;
use std::error::Error;

use attestation_server_custom::{get_attestation_doc, get_hex_attestation_doc};
use axum::{Router, extract::Query, http::StatusCode, routing::get};
use clap::Parser;

fn extract(
    query: &HashMap<String, String>,
    key: &str,
) -> Result<Option<Vec<u8>>, (StatusCode, String)> {
    query
        .get(key)
        .map(|x| hex::decode(x.as_bytes()))
        .transpose()
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to decode {key}: {e:?}"),
            )
        })
}

async fn handle_raw(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let public_key = extract(&query, "public_key")?;
    let user_data = extract(&query, "user_data")?;
    let nonce = extract(&query, "nonce")?;

    get_attestation_doc(public_key, user_data, nonce)
}

async fn handle_hex(
    Query(query): Query<HashMap<String, String>>,
) -> Result<String, (StatusCode, String)> {
    let public_key = extract(&query, "public_key")?;
    let user_data = extract(&query, "user_data")?;
    let nonce = extract(&query, "nonce")?;

    get_hex_attestation_doc(public_key, user_data, nonce)
}

/// http server for handling attestation document requests
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// ip address of the server
    #[arg(short, long, default_value = "127.0.0.1:1350")]
    ip_addr: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let app = Router::new()
        .route("/attestation/raw", get(handle_raw))
        .route("/attestation/hex", get(handle_hex))
        .route("/health", get(|| async { StatusCode::OK }));
    let listener = tokio::net::TcpListener::bind(&cli.ip_addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}
