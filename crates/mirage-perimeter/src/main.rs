//! `mirage-perimeter` — entry point.
//!
//! Boot sequence mirrors `mirage-secd`/`mirage-warden`: harden -> rustls
//! provider -> panic hook -> `run()`. The rustls `CryptoProvider` install
//! is required here (unlike `mirage-warden`, which never dials or
//! terminates TLS) because a face configured with `TlsReal`/`Reality`
//! camouflage runs real server-side TLS inside `strip_tcp_server`.

use std::time::Duration;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Process hardening: no core dumps, no new privs, mlock pages. Called
    // before any secret material (the capsule's wire private key) is
    // loaded — a later SIGSEGV cannot produce a core file with key bytes,
    // and ptrace-attach is blocked.
    let report = mirage_hostsec::harden_process();
    tracing::info!(?report, "[perimeter] host hardening applied");

    // rustls 0.23+ requires a CryptoProvider before any TLS operation.
    match rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()) {
        Ok(()) => tracing::info!("[perimeter] rustls: ring crypto provider installed"),
        Err(_) => tracing::info!("[perimeter] rustls: provider already installed"),
    }

    // Panic hook: log + brief sleep (flush) + exit(1) so systemd / d-watchdog
    // detects the exit and respawns the binary.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".into());
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".into()
        };
        tracing::error!(location = %location, message = %msg, "panic — process exiting");
        std::thread::sleep(Duration::from_millis(mirage_perimeter::PANIC_SLEEP_MS));
        std::process::exit(1);
    }));

    tracing::info!("[perimeter] starting — this box's only public listener");

    let result = mirage_perimeter::run().await;
    match &result {
        Ok(()) => {
            tracing::warn!("[perimeter] run() returned Ok — shutting down");
        }
        Err(e) => {
            tracing::error!("[perimeter] run() failed: {e:#}");
            eprintln!("[FATAL] perimeter: {e:#}");
        }
    }
    std::thread::sleep(Duration::from_millis(mirage_perimeter::SHUTDOWN_GRACE_MS));
    result
}
