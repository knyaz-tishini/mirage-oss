//! Shared on-VPS SQLCipher store — one `state.db` per machine, opened
//! by every Mirage service running on that machine (monitor + node +
//! sentry + mshd as relevant).
//!
//! See `docs/plans/operator-box-extension-plan.md` § "Step B".
//!
//! ## Layout
//!
//! ```text
//! /var/lib/mirage/
//!   state.db          ← SQLCipher; PRAGMA key = the DK
//!   state.db-wal      ← WAL (auto)
//!   state.db-shm      ← shared-mem (auto)
//! ```
//!
//! ZT doctrine (`docs/mirage/doctrine/zt-onboarding-custody-2026-07-12.md`
//! §0-2): on a baked box the DK (SQLCipher master key) is delivered over
//! the wire into db-worker's RAM (`dk_ram`/`key_release`) and
//! [`open_with_key`] is the ONLY opener that exists — there is no
//! on-disk key file at all. The un-baked / dev-box disk-key fallback
//! opener (formerly `open`, reading `<state_dir>/db-key.raw` itself) was
//! deleted 2026-07-14 as part of node baked-or-die: db-worker is the
//! sole RAM-DK holder and the sole reader of this store; every other
//! Mirage service (mirage-node included) must never open it directly.
//! The previous device-fingerprint sealing scheme (`db-key.sealed` +
//! `sealed_secret` AAD) was removed 2026-05-30 — it bricked the DB on
//! every reboot of a cloud VPS whose MAC / machine-id was not stable.
//!
//! ## What lives here
//!
//! - `self_identities`        — one row per service hosted on this box
//! - `operator_pinned`        — operator Ed25519 pub (singleton)
//! - `service_config`         — per-role operational config JSON blob
//!
//! Per-service tables (peer_table, chain_bindings, declared_identities,
//! audit_log, …) are owned by the service crate and live in the SAME
//! file. They add their own `CREATE TABLE IF NOT EXISTS` statements on
//! top of the shared schema during their own boot.
//!
//! ## Compartmentalization
//!
//! Every service on the box runs as root under the same UID and reads
//! the same sealed db key. Hardware-binding is the security boundary —
//! file-level separation between services would be theater under shared
//! root.

#![cfg(any(feature = "shared-store", feature = "sqlcipher"))]

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use thiserror::Error;
#[cfg(feature = "sqlcipher")]
use zeroize::Zeroizing;

/// Canonical state-dir on a Mirage VPS. Every binary opens the same
/// path so identity and config rows are shared across services.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/mirage";
pub const STATE_DB_FILENAME: &str = "state.db";

/// Variant for callers that already hold an unsealed key (operator-box
/// creating the DB locally before upload). The key bytes must be
/// hex-encoded (32 bytes = 64 hex chars).
pub fn open_with_key(state_dir: &Path, key_hex: &str) -> Result<Connection, SharedStoreError> {
    if key_hex.len() != 64 {
        return Err(SharedStoreError::BadKey(format!(
            "db key must be 64 hex chars, got {}",
            key_hex.len()
        )));
    }
    std::fs::create_dir_all(state_dir).map_err(|e| SharedStoreError::Io {
        path: state_dir.to_path_buf(),
        source: e,
    })?;
    let db_path = state_dir.join(STATE_DB_FILENAME);
    let conn = Connection::open(&db_path).map_err(SharedStoreError::Sqlite)?;

    #[cfg(feature = "sqlcipher")]
    {
        // SQLCipher: apply the raw 32-byte key as a hex blob key bypassing
        // the passphrase KDF. `PRAGMA key = "x'<64hex>'"` tells SQLCipher
        // to use the 32 raw bytes directly (no PBKDF2 iteration).
        //
        // The formatted pragma string is transient plaintext (`x'<hex>'`)
        // that otherwise lingers on the heap after SQLCipher has consumed
        // it. Wrap it in `Zeroizing` so it's wiped on drop.
        let pragma_key: Zeroizing<String> = Zeroizing::new(format!("x'{}'", key_hex));
        conn.pragma_update(None, "key", pragma_key.as_str())
            .map_err(SharedStoreError::Sqlite)?;
        drop(pragma_key);
        // Force the cipher to engage: touching sqlite_master will fail
        // immediately if the key is wrong (wrong key / plain-db-with-key).
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|e| {
                SharedStoreError::BadKey(format!(
                    "SQLCipher key rejected (wrong key or plain DB opened with key): {e}"
                ))
            })?;
        tracing::info!("shared_store opened with SQLCipher (encrypted at rest)");
    }
    #[cfg(not(feature = "sqlcipher"))]
    {
        // Plain SQLite path (dev box / opbox native Windows build).
        // Sensitive fields are sealed at the application layer via
        // XChaCha20-Poly1305 + per-machine HKDF. key_hex is intentionally
        // unused here.
        let _ = key_hex;
    }

    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(SharedStoreError::Sqlite)?;
    conn.execute_batch("PRAGMA busy_timeout=5000;")
        .map_err(SharedStoreError::Sqlite)?;
    create_shared_schema(&conn).map_err(SharedStoreError::Sqlite)?;
    run_migrations(&conn).map_err(SharedStoreError::Sqlite)?;
    Ok(conn)
}

/// Run additive migrations for live boxes that already have data.
///
/// Gated on `PRAGMA user_version` so each migration runs exactly once:
/// - v1 → v2: add `egress_ok`, `last_egress_probe_at_ms`, `capabilities_json`
///   to `peer_table`. SQLite `ALTER TABLE ADD COLUMN` with NULL default is
///   safe on live data — no row rewrites, O(1) DDL, backward-compatible
///   (old monitor binary reads the table without these columns → fine).
fn run_migrations(conn: &Connection) -> rusqlite::Result<()> {
    let version = get_user_version(conn)?;
    if version < 2 {
        // Tolerate the column already existing (box was partially migrated).
        // SQLite returns SQLITE_ERROR on duplicate column name — we ignore it.
        let _ = conn
            .execute_batch("ALTER TABLE peer_table ADD COLUMN egress_ok INTEGER;");
        let _ = conn
            .execute_batch("ALTER TABLE peer_table ADD COLUMN last_egress_probe_at_ms INTEGER;");
        let _ = conn
            .execute_batch("ALTER TABLE peer_table ADD COLUMN capabilities_json TEXT;");
        set_user_version(conn, 2)?;
    }
    if version < 3 {
        // `desired_listeners.last_dial_ms` — nullable, set by the monitor
        // whenever it receives a `ListenerActivityReport` WS frame from the
        // node. NULL means the node has never reported activity (either pre-v3
        // node or truly zero traffic). The idle reaper falls back to
        // `chain_bindings.last_used_ms` via COALESCE when this is NULL.
        let _ = conn
            .execute_batch("ALTER TABLE desired_listeners ADD COLUMN last_dial_ms INTEGER;");
        set_user_version(conn, 3)?;
    }
    if version < 4 {
        // Phase 1.11 (memory wave, 2026-05-28): node_egress_matrix
        // was a Stage 6 add. Replaced by mesh_state RAM mirror; no
        // shared-DB persistence anymore. Migration is a one-shot
        // DROP for existing boxes.
        let _ = conn.execute_batch(
            "DROP INDEX IF EXISTS idx_node_egress_to;
             DROP TABLE IF EXISTS node_egress_matrix;",
        );
        set_user_version(conn, 4)?;
    }
    if version < 5 {
        // Phase 1.11: node_metrics was Stage 9; same RAM-only fate.
        let _ = conn.execute_batch("DROP TABLE IF EXISTS node_metrics;");
        set_user_version(conn, 5)?;
    }
    if version < 6 {
        // Phase 1.11 (memory wave): peer_health + node_reported_state
        // also retired. Drop both regardless of when they were created
        // (the create_*_schema paths used to materialise them under
        // CREATE IF NOT EXISTS — that's been removed below).
        let _ = conn.execute_batch(
            "DROP INDEX IF EXISTS idx_peer_health_dst;
             DROP TABLE IF EXISTS peer_health;
             DROP INDEX IF EXISTS idx_reported_state_node;
             DROP TABLE IF EXISTS node_reported_state;",
        );
        set_user_version(conn, 6)?;
    }
    Ok(())
}

/// Create the four shared tables. Idempotent — every service calls this
/// on boot, the first one to run after a wipe materialises them.
///
/// Also runs the additive `migrate_self_identities` pass: existing
/// boxes that were adopted under a pre-Step-B-final schema (no
/// `machine_id` + `signed_envelope_json` columns) get them added in
/// place, with `signed_envelope_json` backfilled from the typed columns
/// plus the legacy `operator_sig` column. Idempotent — second call is a
/// no-op once the new shape is in place.
/// Current shared-store schema version. Bumped when DDL changes in a way
/// that needs a coordinated migration (e.g. legacy monitor SQLite import).
///
/// Version history:
/// - 0 (implicit, pre-step-A): only the 4 shared tables.
/// - 1: monitor tables fold-in (27 legacy tables + `peer_health`); fresh
///   boxes get them from `create_monitor_schema`, existing boxes import
///   from `/var/lib/mirage2monitor-v2/db.sqlite` via
///   `migrate_legacy_monitor_db`.
/// - 2: `peer_table` gains `egress_ok`, `last_egress_probe_at_ms`,
///   `capabilities_json` (all nullable). Live boxes migrate via
///   `ALTER TABLE ADD COLUMN` — no destructive wipe.
/// - 3: `desired_listeners` gains `last_dial_ms` (nullable INTEGER). Tracks
///   the last time a client dialled through this listener (from node's
///   `ListenerActivityReport` WS frame). Used by the idle reaper to prune
///   chains with no recent traffic even when TTL hasn't elapsed.
/// - 4: `node_egress_matrix` created — Stage 6 node-to-node TCP reachability
///   matrix gossiped between monitors, consumed by topology_picker.
/// - 5: `node_metrics` created — Stage 9 cpu/mem/load data from sentry,
///   gossiped fleet-wide, consumed by topology_picker score-based ranking.
pub const SCHEMA_VERSION: i32 = 5;

pub fn create_shared_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        -- Identity slice — one row per service hosted on this box.
        --
        -- `signed_envelope_json` carries the byte-exact serialised
        -- `mirage_core::identity::DeclaredIdentity` so callers don't
        -- have to reconstruct + re-sign the envelope from typed
        -- columns. The typed columns (self_id, role, mesh_id, …) stay
        -- as queryable mirrors of fields inside the envelope.
        CREATE TABLE IF NOT EXISTS self_identities (
            self_id              TEXT PRIMARY KEY,        -- UUID minted by operator
            role                 TEXT NOT NULL UNIQUE,    -- monitor / node-v2 / sentry / mshd / ...
            mesh_id              TEXT NOT NULL,
            machine_id           TEXT NOT NULL,           -- e.g. "ru-hostkey-203.0.113.10"
            pubkey_hex           TEXT NOT NULL,           -- 64 hex; matches keypair_priv pub
            keypair_priv         BLOB NOT NULL,           -- 32 raw bytes, on-box only
            adopted_at_ms        INTEGER NOT NULL,
            signed_envelope_json TEXT NOT NULL            -- DeclaredIdentity JSON (incl operator sig)
        );

        -- Pinned operator pubkey (Ed25519) for verifying inbound gossip
        -- and our own signed envelopes. Singleton row.
        CREATE TABLE IF NOT EXISTS operator_pinned (
            singleton      INTEGER PRIMARY KEY CHECK (singleton = 1),
            pubkey_hex     TEXT NOT NULL,
            adopted_at_ms  INTEGER NOT NULL
        );

        -- Monitor URLs + cert pins (mesh-wide; identical on every VPS,
        -- pushed at adopt, kept in sync by peer gossip).
        CREATE TABLE IF NOT EXISTS service_config (
            role           TEXT PRIMARY KEY,
            config_json    TEXT NOT NULL,
            updated_at_ms  INTEGER NOT NULL
        );
        "#,
    )?;
    create_monitor_schema(conn)?;
    migrate_self_identities(conn)?;
    Ok(())
}

/// Monitor-owned tables. Copied verbatim from
/// `mirage2monitor/crates/monitor/src/store.rs::create_schema` with all
/// ALTER TABLE columns inlined into the CREATE TABLE statements so
/// fresh boxes get the final shape in one shot.
///
/// Also creates `peer_health` (new persistent matrix replacing the
/// previous in-memory `Arc<RwLock<HashMap>>` — see plan B.2).
///
/// `monitor::store::RelayStore::new` no longer runs its own DDL; it
/// delegates to `shared_store::open_with_key`, which calls this.
fn create_monitor_schema(conn: &Connection) -> rusqlite::Result<()> {
    // Stage 10 Phase 1c.5 wipe (2026-05-27): drop dead legacy tables.
    // Idempotent — runs on every boot, no-op once tables are gone.
    // Mirrors the DROP block in `monitor::store::create_schema`.
    conn.execute_batch(
        r#"
        DROP TABLE IF EXISTS probe_reports;
        DROP TABLE IF EXISTS link_metrics;
        DROP TABLE IF EXISTS alerts;
        DROP TABLE IF EXISTS protocol_tests;
        DROP TABLE IF EXISTS runtime_nodes;
        DROP TABLE IF EXISTS monitor_chains;
        "#,
    )?;
    conn.execute_batch(
        r#"
        -- `clients` final shape: base + ALTER columns inlined
        -- (updated_at_ms, origin_lm_id, role, shortname).
        CREATE TABLE IF NOT EXISTS clients (
            client_id            TEXT PRIMARY KEY,
            os                   TEXT NOT NULL,
            version              TEXT NOT NULL,
            supported_transports TEXT NOT NULL,
            registered_at        TEXT NOT NULL,
            last_heartbeat       TEXT,
            heartbeat_json       TEXT,
            updated_at_ms        INTEGER NOT NULL DEFAULT 0,
            origin_lm_id         TEXT NOT NULL DEFAULT '',
            role                 TEXT,
            shortname            TEXT
        );

        CREATE TABLE IF NOT EXISTS sentries (
            sentry_id        TEXT PRIMARY KEY,
            machine_id       TEXT,
            role             TEXT,
            shortname        TEXT,
            registered_at_ms INTEGER NOT NULL,
            last_heartbeat_ms INTEGER,
            load_json        TEXT
        );
        CREATE INDEX IF NOT EXISTS sentries_by_machine ON sentries(machine_id);

        CREATE TABLE IF NOT EXISTS mshds (
            mshd_id          TEXT PRIMARY KEY,
            machine_id       TEXT,
            role             TEXT,
            shortname        TEXT,
            registered_at_ms INTEGER NOT NULL,
            last_heartbeat_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS mshds_by_machine ON mshds(machine_id);

        CREATE TABLE IF NOT EXISTS db_workers (
            worker_id        TEXT PRIMARY KEY,
            machine_id       TEXT,
            shortname        TEXT,
            registered_at_ms INTEGER NOT NULL,
            last_heartbeat_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS db_workers_by_machine ON db_workers(machine_id);

        CREATE TABLE IF NOT EXISTS peers (
            lm_id          TEXT PRIMARY KEY,
            url            TEXT NOT NULL,
            peer_key       TEXT NOT NULL,
            added_at_ms    INTEGER NOT NULL,
            pull_cursor_ms INTEGER NOT NULL DEFAULT 0
        );

        -- `desired_listeners` final shape: base + ALTER (mesh_id) + v3 (last_dial_ms).
        CREATE TABLE IF NOT EXISTS desired_listeners (
            node_id          TEXT NOT NULL,
            listener_id      TEXT NOT NULL,
            spec_json        TEXT NOT NULL,
            fingerprint_hex  TEXT NOT NULL,
            generation       INTEGER NOT NULL,
            updated_at_ms    INTEGER NOT NULL,
            mesh_id          TEXT NOT NULL DEFAULT '',
            last_dial_ms     INTEGER,
            PRIMARY KEY (node_id, listener_id)
        );
        CREATE INDEX IF NOT EXISTS idx_desired_listeners_node
            ON desired_listeners(node_id, generation);

        -- `node_sessions` final shape: base + ALTER (mesh_id, session_expires_at_ms).
        CREATE TABLE IF NOT EXISTS node_sessions (
            node_id              TEXT PRIMARY KEY,
            sentry_id            TEXT NOT NULL,
            session_token        TEXT NOT NULL,
            last_seen_ms         INTEGER NOT NULL,
            current_generation   INTEGER NOT NULL DEFAULT 0,
            supported_axes_json  TEXT NOT NULL DEFAULT '{}',
            external_addr        TEXT,
            version              TEXT,
            registered_at_ms     INTEGER NOT NULL,
            mesh_id              TEXT NOT NULL DEFAULT '',
            session_expires_at_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_node_sessions_sentry
            ON node_sessions(sentry_id);

        -- Phase 1.11 (memory wave, 2026-05-28): node_reported_state
        -- moved to mesh_state RAM. Migration drop happens in
        -- migrate_shared_schema (version < 6). Boxes booting for the
        -- first time skip the CREATE entirely.

        -- `peer_table` final shape: base + ALTER (mesh_id, responsible_monitor_id)
        -- + v2 columns (egress_ok, last_egress_probe_at_ms, capabilities_json).
        CREATE TABLE IF NOT EXISTS peer_table (
            node_id                 TEXT PRIMARY KEY,
            pubkey_hex              TEXT NOT NULL,
            addr                    TEXT NOT NULL,
            labels_json             TEXT NOT NULL DEFAULT '[]',
            updated_at_ms           INTEGER NOT NULL,
            mesh_id                 TEXT NOT NULL DEFAULT '',
            responsible_monitor_id  TEXT NOT NULL DEFAULT '',
            egress_ok               INTEGER,           -- 0/1/NULL
            last_egress_probe_at_ms INTEGER,           -- UNIX ms of last probe
            capabilities_json       TEXT               -- SupportedAxes JSON
        );

        CREATE TABLE IF NOT EXISTS peer_table_generation (
            id             INTEGER PRIMARY KEY CHECK (id = 1),
            generation     INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO peer_table_generation(id, generation) VALUES (1, 0);

        -- `chain_bindings` final shape: base + 7 ALTER columns inlined.
        CREATE TABLE IF NOT EXISTS chain_bindings (
            chain_id        TEXT PRIMARY KEY,
            spec_json       TEXT NOT NULL,
            updated_at_ms   INTEGER NOT NULL,
            mesh_id         TEXT NOT NULL DEFAULT '',
            auto            INTEGER NOT NULL DEFAULT 0,
            expires_at_ms   INTEGER NOT NULL DEFAULT 0,
            last_used_ms    INTEGER NOT NULL DEFAULT 0,
            requester_role  TEXT    NOT NULL DEFAULT 'operator',
            axis_spec_json  TEXT,
            bind_ports_json TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS chain_bindings_generation (
            id             INTEGER PRIMARY KEY CHECK (id = 1),
            generation     INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO chain_bindings_generation(id, generation) VALUES (1, 0);

        CREATE TABLE IF NOT EXISTS chain_owners (
            chain_id        TEXT PRIMARY KEY,
            client_id       TEXT NOT NULL,
            requester_role  TEXT NOT NULL DEFAULT 'client',
            claimed_at_ms   INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_chain_owners_client
            ON chain_owners(client_id, claimed_at_ms);

        CREATE TABLE IF NOT EXISTS chain_port_assignments (
            chain_id        TEXT NOT NULL,
            hop_position    INTEGER NOT NULL,
            node_id         TEXT NOT NULL,
            bind_port       INTEGER NOT NULL,
            kind            TEXT NOT NULL,
            assigned_at_ms  INTEGER NOT NULL,
            PRIMARY KEY (chain_id, hop_position)
        );
        CREATE INDEX IF NOT EXISTS idx_chain_port_assignments_node
            ON chain_port_assignments(node_id, bind_port);

        -- `monitors` final shape: base + ALTER (quiesced) inlined. `quiesced`
        -- was originally added via the monitor crate's own idempotent
        -- ALTER TABLE migration (`mirage2monitor/crates/monitor/src/store.rs`)
        -- — inlined here too so any reader that opens this file via
        -- `shared_store::open_with_key` alone (e.g. db-worker, before the
        -- monitor has ever booted on this box) sees the real column instead
        -- of failing `COALESCE(quiesced, 0)` with "no such column".
        CREATE TABLE IF NOT EXISTS monitors (
            mesh_id             TEXT NOT NULL,
            monitor_id          TEXT NOT NULL,
            monitor_pubkey_hex  TEXT NOT NULL,
            public_addr         TEXT NOT NULL,
            labels_json         TEXT NOT NULL DEFAULT '[]',
            updated_at_ms       INTEGER NOT NULL,
            origin_lm_id        TEXT NOT NULL DEFAULT '',
            quiesced            INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (mesh_id, monitor_id)
        );

        -- `dynamic_api_keys` final shape: base + ALTER (expires_at_ms).
        CREATE TABLE IF NOT EXISTS dynamic_api_keys (
            hash              TEXT PRIMARY KEY,
            role              TEXT NOT NULL,
            label             TEXT NOT NULL DEFAULT '',
            mesh_id           TEXT NOT NULL,
            created_at_ms     INTEGER NOT NULL,
            source_lm_id      TEXT NOT NULL,
            expires_at_ms     INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_dynkeys_mesh
            ON dynamic_api_keys(mesh_id, created_at_ms);

        CREATE TABLE IF NOT EXISTS peer_keys_outbound (
            target_lm_id  TEXT PRIMARY KEY,
            peer_key_raw  TEXT NOT NULL,
            issued_at_ms  INTEGER NOT NULL,
            rotates_at_ms INTEGER NOT NULL,
            label         TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS declared_identities (
            self_id        TEXT PRIMARY KEY,
            machine_id     TEXT NOT NULL,
            mesh_id        TEXT NOT NULL,
            role           TEXT NOT NULL,
            pubkey_hex     TEXT NOT NULL,
            adopted_at_ms  INTEGER NOT NULL,
            revoked        INTEGER NOT NULL DEFAULT 0,
            revoked_at_ms  INTEGER,
            payload_json   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_declared_identities_machine
            ON declared_identities(machine_id);
        CREATE INDEX IF NOT EXISTS idx_declared_identities_mesh
            ON declared_identities(mesh_id);
        CREATE INDEX IF NOT EXISTS idx_declared_identities_pubkey
            ON declared_identities(pubkey_hex);

        -- `audit_log` final shape: base + ALTER (prev_hash).
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_ms    INTEGER NOT NULL,
            role            TEXT NOT NULL,
            api_key_label   TEXT,
            method          TEXT NOT NULL,
            path            TEXT NOT NULL,
            source_ip       TEXT NOT NULL,
            user_agent      TEXT,
            success         INTEGER NOT NULL,
            status_code     INTEGER NOT NULL,
            details         TEXT,
            prev_hash       TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp_ms);
        CREATE INDEX IF NOT EXISTS idx_audit_role ON audit_log(role, timestamp_ms);

        -- NEW (plan B.2): persistent peer-health matrix. Replaces the
        -- in-memory `Arc<RwLock<HashMap<src, HashMap<dst, ProbeRecord>>>>`
        -- so monitor restart doesn't blank the matrix and every reader
        -- (topology_picker, /relay/links) hits a single source of truth.
        --
        -- Keyed by `lm_id` (monitor UUID) to match the existing gossip
        -- wire format (`PeerEvent::PeerHealthUpsert { origin_lm_id,
        -- target_lm_id, ... }`). A later cosmetic pass can rename to
        -- Phase 1.11 (memory wave, 2026-05-28): peer_health,
        -- node_egress_matrix and node_metrics were Stage 6/9 tables
        -- that live now in mesh_state RAM. Fresh boxes skip the
        -- CREATE; pre-existing boxes get DROP'd in migrate_shared_schema
        -- (version < 4/5/6).

        -- Mesh-wide observed CIDRs: one row per (cidr, source_lm_id).
        -- Replicated via LiveCidrUpsert gossip (LWW by updated_at_ms).
        -- Nothing writes rows yet — schema only.
        CREATE TABLE IF NOT EXISTS live_cidr (
            cidr            TEXT NOT NULL,
            source_lm_id    TEXT NOT NULL,
            first_seen_ms   INTEGER NOT NULL,
            last_seen_ms    INTEGER NOT NULL,
            updated_at_ms   INTEGER NOT NULL,
            PRIMARY KEY (cidr, source_lm_id)
        );

        -- Operator-managed static CIDR lists (e.g. block/allow sets).
        -- Replicated via ExternalCidrUpsert gossip (LWW by updated_at_ms).
        -- Nothing writes rows yet — schema only.
        CREATE TABLE IF NOT EXISTS external_cidr (
            list_id         TEXT NOT NULL,
            cidr            TEXT NOT NULL,
            label           TEXT,
            updated_at_ms   INTEGER NOT NULL,
            PRIMARY KEY (list_id, cidr)
        );

        -- Per-scope application split config (routing policy key/value).
        -- Replicated via AppSplitConfigUpsert gossip (LWW by updated_at_ms).
        -- Nothing writes rows yet — schema only.
        CREATE TABLE IF NOT EXISTS app_split_config (
            scope_id        TEXT NOT NULL,
            config_key      TEXT NOT NULL,
            config_json     TEXT NOT NULL,
            updated_at_ms   INTEGER NOT NULL,
            PRIMARY KEY (scope_id, config_key)
        );

        -- arc2.7: secd's durable desired operating-state (last signed
        -- `SetPolicy`/`SetPatchSchedule` directive per box). Stores the
        -- WHOLE signed `SecdDirective` blob (serde_json bytes), not decoded
        -- scalars, so secd's boot-seed path re-runs the exact
        -- `apply_directive` dispatch (operator-sig re-verify) — zero new
        -- trust surface. LWW by `updated_at_ms` (the directive's
        -- issued-at). One row per (box, kind) — a state row, not a growing
        -- queue. See `docs/mirage/plans/arc2.7-secd-durability-2026-07-08.md`.
        CREATE TABLE IF NOT EXISTS secd_desired_state (
            machine_id     TEXT NOT NULL,
            kind           TEXT NOT NULL,          -- 'set_policy' | 'set_patch_schedule'
            directive_blob BLOB NOT NULL,           -- serde_json bytes of the full signed SecdDirective
            updated_at_ms  INTEGER NOT NULL,
            PRIMARY KEY (machine_id, kind)
        );

        -- mshd blob delivery (etape 2). Operator stages encrypted blobs here;
        -- mshd pulls them over its V9 wire. Monitor stores only ciphertext.
        -- `delivered_at_ms` is NULL until mshd acks delivery.
        -- `manifest_json` is the full MshdBlobManifest for the mshd response.
        CREATE TABLE IF NOT EXISTS mshd_blobs (
            blob_id         TEXT PRIMARY KEY,
            mshd_id         TEXT NOT NULL,
            dest_path       TEXT NOT NULL,
            total_bytes     INTEGER NOT NULL,
            chunk_size      INTEGER NOT NULL,
            chunk_count     INTEGER NOT NULL,
            plain_sha256    BLOB NOT NULL,
            op_mesh_pub     TEXT NOT NULL,
            op_sig          BLOB NOT NULL,
            created_at_ms   INTEGER NOT NULL,
            delivered_at_ms INTEGER,
            manifest_json   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mshd_blobs_mshd
            ON mshd_blobs(mshd_id, delivered_at_ms);

        CREATE TABLE IF NOT EXISTS mshd_blob_chunks (
            blob_id TEXT NOT NULL,
            idx     INTEGER NOT NULL,
            nonce   BLOB NOT NULL,
            ct      BLOB NOT NULL,
            PRIMARY KEY (blob_id, idx)
        );

        -- T1b: per-machine VPS telemetry snapshot.
        -- One row per machine (LWW by updated_at_ms). Bounded: 1 row/machine,
        -- overwritten on every sentry heartbeat, gossiped fleet-wide so any
        -- monitor can answer /fleet/health without hitting the originating box.
        CREATE TABLE IF NOT EXISTS machine_state (
            machine_id        TEXT PRIMARY KEY,
            mem_pct           REAL    NOT NULL DEFAULT 0.0,
            mem_total_mb      INTEGER NOT NULL DEFAULT 0,
            monitor_rss_mb    INTEGER NOT NULL DEFAULT 0,
            disk_pct          REAL    NOT NULL DEFAULT 0.0,
            disk_free_mb      INTEGER NOT NULL DEFAULT 0,
            swap_pct          REAL    NOT NULL DEFAULT 0.0,
            journal_mb        INTEGER NOT NULL DEFAULT 0,
            db_mb             INTEGER NOT NULL DEFAULT 0,
            oom_count_1h      INTEGER NOT NULL DEFAULT 0,
            last_crash_reason TEXT,
            updated_at_ms     INTEGER NOT NULL DEFAULT 0,
            origin_lm_id      TEXT    NOT NULL DEFAULT ''
        );
        "#,
    )?;
    Ok(())
}

/// Additive in-place migration for pre-Step-B-final boxes.
///
/// Pre-final schema (the one operator-box drops created during early
/// adopts before commit 3dec975 in mirage2web) had:
///   self_identities(self_id, role, mesh_id, pubkey_hex, keypair_priv,
///                   operator_sig, adopted_at_ms)
///
/// Final schema adds `machine_id` + `signed_envelope_json`. We can't
/// derive `machine_id` from any in-row column — we read it from the
/// `operator_pinned` row's `adopted_at_ms`? No, that's not it either.
/// The machine_id IS knowable: it's the same string for every row in
/// the table (one machine, many roles), and operator-box wrote it into
/// the install bundle that produced these rows. But we don't have it
/// here. The pragmatic fallback: leave `machine_id` empty and let
/// callers that need it pull it from the embedded
/// `signed_envelope_json` instead — the JSON DOES carry it.
///
/// `signed_envelope_json` we CAN reconstruct: serialize a synthetic
/// DeclaredIdentity built from the typed columns + the legacy
/// `operator_sig` hex string.
///
/// If the pre-final table never existed (fresh box), this function is
/// a no-op — `PRAGMA table_info` already shows the new columns and we
/// return early.
fn migrate_self_identities(conn: &Connection) -> rusqlite::Result<()> {
    // Pull existing column set.
    let mut stmt = conn.prepare("PRAGMA table_info(self_identities)")?;
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(Result::ok)
        .collect();
    drop(stmt);
    let has = |name: &str| cols.iter().any(|c| c == name);

    let needs_machine_id = !has("machine_id");
    let needs_signed_envelope = !has("signed_envelope_json");
    let has_legacy_operator_sig = has("operator_sig");

    // Fast path: table already in final shape and no legacy column left.
    if !needs_machine_id && !needs_signed_envelope && !has_legacy_operator_sig {
        return Ok(());
    }

    // Full table rebuild — needed because SQLite ALTER TABLE can't drop
    // the legacy `operator_sig NOT NULL` column, and leaving it would
    // make every new INSERT (which only supplies the new columns) fail
    // with `NOT NULL constraint failed: self_identities.operator_sig`.
    //
    // Steps:
    //  1. Read every row from the existing table into memory (small —
    //     one row per role, at most a handful per box).
    //  2. CREATE TABLE self_identities_new with the final shape.
    //  3. INSERT each row, backfilling signed_envelope_json from
    //     typed columns + the legacy operator_sig (if it was present).
    //  4. DROP old, RENAME new → self_identities.
    let mut rows: Vec<(String, String, String, String, String, Vec<u8>, i64, String)> = Vec::new();

    // SELECT pre-computed column list — we have to spell out the columns
    // we know exist on either shape.
    let select_sql = if has_legacy_operator_sig && !needs_signed_envelope {
        // Both old `operator_sig` and new `signed_envelope_json` present.
        "SELECT self_id, role, mesh_id, COALESCE(machine_id, ''), pubkey_hex,
                keypair_priv, adopted_at_ms,
                CASE WHEN signed_envelope_json='' THEN operator_sig ELSE signed_envelope_json END
         FROM self_identities"
    } else if has_legacy_operator_sig {
        // Legacy table without signed_envelope_json column at all.
        "SELECT self_id, role, mesh_id, '', pubkey_hex, keypair_priv,
                adopted_at_ms, operator_sig
         FROM self_identities"
    } else if !needs_signed_envelope && !needs_machine_id {
        // Final shape (no legacy column to drop) — already handled above,
        // but kept for safety.
        return Ok(());
    } else {
        // Mixed: needs machine_id and/or signed_envelope_json but no
        // legacy operator_sig to source from. Backfill with empty
        // strings so future operator-box adopts overwrite via REPLACE.
        "SELECT self_id, role, mesh_id, COALESCE(machine_id, ''), pubkey_hex,
                keypair_priv, adopted_at_ms, ''
         FROM self_identities"
    };
    let mut select = conn.prepare(select_sql)?;
    let mapped = select.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Vec<u8>>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, String>(7)?,
        ))
    })?;
    for r in mapped {
        rows.push(r?);
    }
    drop(select);

    // CREATE TABLE in the final shape under a temporary name.
    conn.execute_batch(
        "DROP TABLE IF EXISTS self_identities_new;
         CREATE TABLE self_identities_new (
             self_id              TEXT PRIMARY KEY,
             role                 TEXT NOT NULL UNIQUE,
             mesh_id              TEXT NOT NULL,
             machine_id           TEXT NOT NULL,
             pubkey_hex           TEXT NOT NULL,
             keypair_priv         BLOB NOT NULL,
             adopted_at_ms        INTEGER NOT NULL,
             signed_envelope_json TEXT NOT NULL
         );",
    )?;

    // Replay rows. If the eighth column still looks like a raw 64-hex
    // signature (legacy shape) reconstruct a synthetic envelope JSON
    // around it; otherwise treat it as the existing envelope JSON.
    for (self_id, role_slug, mesh_id, machine_id, pubkey_hex, keypair_priv, adopted_at_ms, env_or_sig) in
        rows
    {
        let envelope_json = if env_or_sig.starts_with('{') {
            // Already a JSON envelope; trust it.
            env_or_sig
        } else if env_or_sig.is_empty() {
            // No source data — leave a minimal stub so the NOT NULL
            // constraint passes. Operator-box will overwrite on next adopt.
            let role_value = parse_role_slug(&role_slug);
            serde_json::json!({
                "self_id": self_id,
                "machine_id": machine_id,
                "mesh_id": mesh_id,
                "role": role_value,
                "pubkey_hex": pubkey_hex,
                "adopted_at_ms": adopted_at_ms,
                "revoked": false,
                "operator_sig": "",
            })
            .to_string()
        } else {
            // Legacy raw operator_sig hex. Wrap it in a synthetic envelope.
            let role_value = parse_role_slug(&role_slug);
            serde_json::json!({
                "self_id": self_id,
                "machine_id": machine_id,
                "mesh_id": mesh_id,
                "role": role_value,
                "pubkey_hex": pubkey_hex,
                "adopted_at_ms": adopted_at_ms,
                "revoked": false,
                "operator_sig": env_or_sig,
            })
            .to_string()
        };

        conn.execute(
            "INSERT INTO self_identities_new
                 (self_id, role, mesh_id, machine_id, pubkey_hex,
                  keypair_priv, adopted_at_ms, signed_envelope_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                self_id,
                role_slug,
                mesh_id,
                machine_id,
                pubkey_hex,
                keypair_priv,
                adopted_at_ms,
                envelope_json,
            ],
        )?;
    }

    // Swap.
    conn.execute_batch(
        "DROP TABLE self_identities;
         ALTER TABLE self_identities_new RENAME TO self_identities;",
    )?;
    Ok(())
}

/// Tables migrated from the legacy plain-SQLite monitor DB into the
/// shared SQLCipher store. Order matters: parent tables before children
/// (e.g. `peer_table_generation` before `peer_table` is fine; FKs
/// aren't declared but readability matches the create_monitor_schema
/// declaration order).
const LEGACY_MONITOR_TABLES: &[&str] = &[
    "probe_reports",
    "link_metrics",
    "alerts",
    "protocol_tests",
    "clients",
    "sentries",
    "mshds",
    "db_workers",
    "runtime_nodes",
    "peers",
    "desired_listeners",
    "node_sessions",
    "node_reported_state",
    "peer_table",
    "peer_table_generation",
    "chain_bindings",
    "chain_bindings_generation",
    "chain_owners",
    "chain_port_assignments",
    "monitors",
    "monitor_chains",
    "dynamic_api_keys",
    "peer_keys_outbound",
    "declared_identities",
    "audit_log",
];

/// Outcome of a legacy-DB import. Caller logs the per-table counts.
#[derive(Debug, Default)]
pub struct LegacyMigrationReport {
    pub rows_per_table: Vec<(String, i64)>,
    pub skipped_missing_tables: Vec<String>,
}

/// Import the legacy plain-SQLite monitor DB at `legacy_path` into the
/// already-open `shared` connection. Runs once: callers gate on
/// `PRAGMA user_version < SCHEMA_VERSION` and the file's existence.
///
/// Strategy: `ATTACH DATABASE` the legacy file as `legacy`, then for
/// every table in `LEGACY_MONITOR_TABLES` issue
/// `INSERT OR IGNORE INTO main.<t> SELECT * FROM legacy.<t>`. The
/// column shape MUST match — `create_monitor_schema` materialised
/// the same DDL the legacy `monitor::store::create_schema` did at
/// the time of cutover, with every ALTER column inlined.
///
/// `legacy_password = None` for the historical unencrypted file. Pass
/// the SQLCipher master password for boxes that had the legacy
/// `[db_password]` config set (Stage 1 ZT pass — 9/9 staging-v2).
///
/// On success, the caller MUST bump `PRAGMA user_version` to
/// `SCHEMA_VERSION` and rename `legacy_path` so this never re-runs.
pub fn migrate_legacy_monitor_db(
    shared: &Connection,
    legacy_path: &Path,
    legacy_password: Option<&str>,
) -> Result<LegacyMigrationReport, SharedStoreError> {
    let legacy_str = legacy_path.to_string_lossy().to_string();
    let escaped_path = legacy_str.replace('\'', "''");
    // SQLCipher inherits the main connection's key for every ATTACHed
    // database, so plain SQLite files attached without an explicit
    // empty-key clause come back as "file is not a database". The
    // SQLCipher way to attach a plaintext file is `ATTACH ... KEY ''`;
    // sealed legacy files use the password they were originally keyed
    // with.
    let key_clause = legacy_password.unwrap_or("");
    let escaped_key = key_clause.replace('\'', "''");
    shared
        .execute_batch(&format!(
            "ATTACH DATABASE '{escaped_path}' AS legacy KEY '{escaped_key}';"
        ))
        .map_err(SharedStoreError::Sqlite)?;

    let mut report = LegacyMigrationReport::default();

    let mut stmt = shared
        .prepare(
            "SELECT name FROM legacy.sqlite_master \
             WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )
        .map_err(SharedStoreError::Sqlite)?;
    let present: std::collections::HashSet<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(SharedStoreError::Sqlite)?
        .filter_map(Result::ok)
        .collect();
    drop(stmt);

    for &table in LEGACY_MONITOR_TABLES {
        if !present.contains(table) {
            report.skipped_missing_tables.push(table.to_string());
            continue;
        }
        let sql = format!(
            "INSERT OR IGNORE INTO main.{table} SELECT * FROM legacy.{table}"
        );
        let rows = shared
            .execute(&sql, [])
            .map_err(SharedStoreError::Sqlite)? as i64;
        report.rows_per_table.push((table.to_string(), rows));
    }

    shared
        .execute_batch("DETACH DATABASE legacy;")
        .map_err(SharedStoreError::Sqlite)?;
    Ok(report)
}

/// Stamp the shared connection with `PRAGMA user_version = v`. Called
/// after a successful one-shot migration so the next boot skips it.
pub fn set_user_version(conn: &Connection, v: i32) -> rusqlite::Result<()> {
    conn.execute_batch(&format!("PRAGMA user_version = {v};"))
}

/// Read `PRAGMA user_version` (0 on a fresh DB).
pub fn get_user_version(conn: &Connection) -> rusqlite::Result<i32> {
    conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i32>(0))
}

/// Map a role slug back to the serialized `ServiceRole` JSON value
/// shape (tagged `kind`, with `epoch` for node variants).
fn parse_role_slug(slug: &str) -> serde_json::Value {
    use serde_json::json;
    match slug {
        "node-v1" => json!({"kind": "node", "epoch": "v1"}),
        "node-v2" => json!({"kind": "node", "epoch": "v2"}),
        "node-v3" => json!({"kind": "node", "epoch": "v3"}),
        "node-sa" => json!({"kind": "node", "epoch": "sa"}),
        other => json!({"kind": other.replace('-', "_")}),
    }
}

#[derive(Debug, Error)]
pub enum SharedStoreError {
    #[error("operator-delivered db-key not found at {path}; \
             baked boxes never need this file (DK rides the wire into RAM) — \
             an un-baked box recovers via `POST /inventory/deliver-db-key/<machine>`")]
    KeyFileMissing { path: String },
    #[error("io on {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("sqlite: {0}")]
    Sqlite(rusqlite::Error),
    #[error("bad key: {0}")]
    BadKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use uuid::Uuid;

    fn tmp_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mirage-core-shared-store-{label}-{}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        p
    }

    #[test]
    fn migrate_self_identities_adds_columns_and_backfills() {
        // Build a connection by hand with the pre-final schema, insert a
        // legacy row, then run the migration and verify the new columns
        // exist + signed_envelope_json got backfilled with the expected JSON.
        let conn = Connection::open_in_memory().expect("in-memory");
        conn.execute_batch(
            "CREATE TABLE self_identities (
                 self_id        TEXT PRIMARY KEY,
                 role           TEXT NOT NULL UNIQUE,
                 mesh_id        TEXT NOT NULL,
                 pubkey_hex     TEXT NOT NULL,
                 keypair_priv   BLOB NOT NULL,
                 operator_sig   TEXT NOT NULL,
                 adopted_at_ms  INTEGER NOT NULL
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO self_identities
                 (self_id, role, mesh_id, pubkey_hex, keypair_priv,
                  operator_sig, adopted_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "11111111-2222-3333-4444-555555555555",
                "node-v2",
                "v3-staging",
                "aa".repeat(32),
                vec![0xCCu8; 32],
                "ff".repeat(64),
                1_700_000_000_000i64,
            ],
        )
        .unwrap();

        // Apply only the migration (CREATE TABLE IF NOT EXISTS already
        // exists so the full create_shared_schema would also work; calling
        // the migration directly keeps the assertion focused).
        migrate_self_identities(&conn).expect("migrate");

        // Columns are present.
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(self_identities)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(cols.iter().any(|c| c == "machine_id"), "machine_id missing");
        assert!(
            cols.iter().any(|c| c == "signed_envelope_json"),
            "signed_envelope_json missing"
        );

        // Backfill produced a JSON envelope that parses and carries the
        // expected role + mesh_id + operator_sig.
        let envelope: String = conn
            .query_row(
                "SELECT signed_envelope_json FROM self_identities WHERE self_id = ?1",
                params!["11111111-2222-3333-4444-555555555555"],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!envelope.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(parsed["self_id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(parsed["mesh_id"], "v3-staging");
        assert_eq!(parsed["role"]["kind"], "node");
        assert_eq!(parsed["role"]["epoch"], "v2");
        assert_eq!(parsed["operator_sig"], "ff".repeat(64));

        // Idempotent — second call doesn't fail or re-fill.
        migrate_self_identities(&conn).expect("second migrate");
        let envelope_again: String = conn
            .query_row(
                "SELECT signed_envelope_json FROM self_identities WHERE self_id = ?1",
                params!["11111111-2222-3333-4444-555555555555"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(envelope, envelope_again);
    }

    #[test]
    fn migrate_self_identities_noop_on_fresh_schema() {
        // Final schema from the start → migration is a no-op + doesn't error.
        let conn = Connection::open_in_memory().expect("in-memory");
        create_shared_schema(&conn).unwrap();
        // Second call also fine.
        migrate_self_identities(&conn).expect("noop");
    }

    #[test]
    fn open_with_key_creates_schema() {
        let dir = tmp_dir("create");
        let key_hex = hex::encode([0xAAu8; 32]);
        let conn = open_with_key(&dir, &key_hex).expect("open");

        // All four shared tables exist.
        for t in [
            "self_identities",
            "operator_pinned",
            "service_config",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![t],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "table {t} missing");
        }
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(feature = "sqlcipher")]
    fn open_with_wrong_key_fails() {
        // SQLCipher only: a wrong 32-byte key is rejected on the first read.
        // With plain SQLite the key is ignored, so this assertion would be
        // meaningless — gate the test to the sqlcipher feature path only.
        let dir = tmp_dir("wrongkey");
        let key1 = hex::encode([0x11u8; 32]);
        {
            let conn = open_with_key(&dir, &key1).expect("first open");
            conn.execute(
                "INSERT INTO operator_pinned (singleton, pubkey_hex, adopted_at_ms)
                 VALUES (1, ?1, ?2)",
                params!["deadbeef".repeat(8), 1_700_000_000_000i64],
            )
            .unwrap();
        }
        let key2 = hex::encode([0x22u8; 32]);
        let conn = open_with_key(&dir, &key2).expect("open with wrong key still 'succeeds'");
        // SQLCipher only surfaces the wrong key on the first read.
        let row = conn.query_row(
            "SELECT pubkey_hex FROM operator_pinned WHERE singleton = 1",
            [],
            |r| r.get::<_, String>(0),
        );
        assert!(row.is_err(), "wrong-key read must fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_with_key_roundtrip() {
        // Open with a fixed key, write a row, drop the connection, reopen
        // with the SAME key hex (mirrors db-worker's RAM-DK opener path —
        // no on-disk key file anywhere in this crate any more) and confirm
        // the row survives.
        let dir = tmp_dir("opkey");
        let key_hex = hex::encode([0xBBu8; 32]);
        let conn1 = open_with_key(&dir, &key_hex).expect("open with key");
        conn1
            .execute(
                "INSERT INTO operator_pinned (singleton, pubkey_hex, adopted_at_ms)
                 VALUES (1, ?1, ?2)",
                params!["a".repeat(64), 1_700_000_000_000i64],
            )
            .unwrap();
        drop(conn1);
        // Reopen — same key, row visible.
        let conn2 = open_with_key(&dir, &key_hex).expect("reopen with key");
        let pubhex: String = conn2
            .query_row(
                "SELECT pubkey_hex FROM operator_pinned WHERE singleton = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pubhex, "a".repeat(64));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
