//! Build-time construction of the send-first decompression bomb payload.
//!
//! Moved verbatim from `mirage-secd/build.rs` (that crate's own bomb-build
//! step) when `decoy.rs`/`bomb.rs` moved to this crate — see `src/lib.rs`'s
//! module doc for why.
//!
//! Generates a nested-gzip blob at `cargo build` time and writes it to
//! `$OUT_DIR/decoy_bomb.bin`. The runtime binary only ever `write_all`s this
//! static blob (`src/bomb.rs`'s `include_bytes!`) — it contains ZERO
//! decompression code and never processes anything an attacker sends. The
//! `flate2` dependency lives ONLY in `[build-dependencies]`; it is not
//! linked into anything that depends on this crate.
//!
//! A small ASCII payload is gzip-compressed `BOMB_NEST_LAYERS` times in
//! succession (each layer's compressed output becomes the next layer's
//! plaintext input). A conforming gzip client recursively decompressing every
//! layer expands the tiny on-wire blob by roughly
//! `BOMB_INNER_SIZE^BOMB_NEST_LAYERS`-ish growth per additional layer — the
//! exact multi-GB expansion ratio is not load-bearing; what matters is the
//! wire bytes stay tiny (see `src/bomb.rs` doc comment for the safety
//! argument) while a naive recursive-gunzip client blows up.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;

/// Number of nested gzip layers. Each layer adds another `gunzip` pass a
/// naive automated harvester must perform before it can even inspect the
/// "real" payload — and each pass multiplies the decompressed size.
const BOMB_NEST_LAYERS: usize = 6;

/// Size (bytes) of the innermost plaintext blob, before any gzip layer is
/// applied. Kept small and constant — the growth comes from nesting, not
/// from a large seed payload.
const BOMB_INNER_SIZE: usize = 1024 * 1024; // 1 MiB of compressible zeros

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    build_decompression_bomb();
}

fn build_decompression_bomb() {
    // Innermost plaintext: a single repeated byte compresses extremely well
    // at every nesting layer, keeping the final on-wire blob small even
    // after BOMB_NEST_LAYERS rounds of gzip.
    let mut payload: Vec<u8> = vec![0u8; BOMB_INNER_SIZE];

    for _ in 0..BOMB_NEST_LAYERS {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&payload)
            .expect("gzip encode must not fail on an in-memory buffer");
        payload = encoder
            .finish()
            .expect("gzip finish must not fail on an in-memory buffer");
    }

    let out_path = out_dir().join("decoy_bomb.bin");
    fs::write(&out_path, &payload).unwrap_or_else(|e| {
        panic!("write bomb blob to {}: {e}", out_path.display());
    });

    println!(
        "cargo:warning=[perimeter/build] decompression-bomb blob built: {} bytes on wire ({} nested gzip layers, {} bytes innermost)",
        payload.len(),
        BOMB_NEST_LAYERS,
        BOMB_INNER_SIZE
    );
}

fn out_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"))
}
