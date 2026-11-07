//! The `mirage-vpn` program: a server and a client.
//!
//! ```text
//!   mirage-vpn keygen --out server.key
//!   mirage-vpn serve --config server.json
//!   mirage-vpn connect --config client.json
//!   mirage-vpn propose --config server.json
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mirage_core::crypto::KeyPair;
use mirage_vpn_cli::config::{encode_public, encode_secret};
use mirage_vpn_cli::{client, config, propose, server};

#[derive(Parser)]
#[command(
    name = "mirage-vpn",
    version,
    about = "The Mirage VPN: a server and a client"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make a key pair. The private key goes into the file, the public key goes to the screen.
    Keygen {
        /// Where the private key is written.
        #[arg(long, default_value = "mirage-vpn.key")]
        out: PathBuf,
    },
    /// Serve the VPN.
    Serve {
        /// The config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Connect to a server and serve a local SOCKS5.
    Connect {
        /// The config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Publish what this box can be reached on: its faces and its public key.
    ///
    /// This is what the operator reads to build the subscriber's artefact.
    /// The secret is never printed.
    Propose {
        /// The config file.
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Run the command.
async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Keygen { out } => keygen(&out)?,
        Command::Serve { config: path } => {
            let config = config::ServerConfig::load(&path)?;
            let handle = server::start(config).await?;
            for (name, address) in &handle.listeners {
                println!("{name}: {address}");
            }
            println!("the server is up");
            // The server runs until it is stopped.
            std::future::pending::<()>().await;
        }
        Command::Connect { config: path } => {
            let config = config::ClientConfig::load(&path)?;
            let handle = client::start(config).await?;
            println!("socks5: {}", handle.socks5);
            println!("the client is up");
            // The client runs until it is stopped.
            std::future::pending::<()>().await;
        }
        Command::Propose { config: path } => {
            let config = config::ServerConfig::load(&path)?;
            let proposal = propose::Proposal::of(&config)?;
            println!("{}", proposal.to_json()?);
        }
    }
    Ok(())
}

/// Make a key pair.
///
/// The private key goes into the file — it is never printed: a key that is
/// shown on the screen is a key that ends up in a screenshot.
fn keygen(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KeyPair::generate();
    std::fs::write(out, format!("{}\n", encode_secret(&keypair)))?;
    println!("private key: {}", out.display());
    println!("public key:  {}", encode_public(&keypair));
    Ok(())
}
