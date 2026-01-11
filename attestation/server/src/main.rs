use std::error::Error;

use axum::{Router, http::StatusCode, routing::get};
use clap::Parser;

/// http server for handling attestation document requests
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// listen address of the server (e.g. 127.0.0.1:1300)
    #[arg(short, long)]
    listen_addr: String,

    /// path to public key file (e.g. /app/id.pub)
    #[arg(short, long)]
    public_key: String,

    /// path to user data file (e.g. /app/init-params-digest)
    #[arg(long)]
    user_data: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // leak in order to get a static slice
    // okay to do since it will get cleaned up on exit
    let public_key: &'static [u8] = std::fs::read(cli.public_key)?.leak::<'static>();
    let user_data: &'static [u8] = cli
        .user_data
        .and_then(|x| std::fs::read(x).ok())
        .unwrap_or(Vec::new())
        .leak::<'static>();

    let app = Router::new()
        .route(
            "/attestation/raw",
            get(|| async {
                attestation_server::get_attestation_doc(
                    Some(public_key.into()),
                    Some(user_data.into()),
                    None,
                )
            }),
        )
        .route(
            "/attestation/hex",
            get(|| async {
                attestation_server::get_hex_attestation_doc(
                    Some(public_key.into()),
                    Some(user_data.into()),
                    None,
                )
            }),
        )
        .route("/health", get(|| async { StatusCode::OK }));

    println!("Listening on {}", cli.listen_addr);
    let listener = tokio::net::TcpListener::bind(&cli.listen_addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}
