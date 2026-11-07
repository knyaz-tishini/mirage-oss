//! `m1r4g3-server` — the standalone box's own binary.
//!
//! * `init` — mint or load the box's identity, sign the subscriber
//!   allowlist, and write the one artefact the customer needs
//!   (`client.link`). Prints the artefact's path — never a secret.
//! * `env` — print a complete `server.env` for `all`, `quic`, or
//!   `quic-mirage`, and exit. Camouflage is only inside Mirage, and these
//!   profiles set it to none.
//! * `health` — check that the three files on the box are present and
//!   valid. Exit 0 when they are, 1 when they are not.
//! * `propose` — say what this box COULD publish: the ports that are free
//!   on it and the set of faces a person is offered. It proposes; it does
//!   not choose.
//! * `run` — build the box's control plane from its chain spec and serve the
//!   chain splice until interrupted.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |---|---|
//! | 0 | the command did what it was asked to do |
//! | 1 | the command could not do it — a usage, configuration or I/O failure |
//!
//! `run` serves until it is interrupted; it exits 0 when the splice is
//! closed cleanly and 1 when it could not be brought up at all.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mirage_core::config::TransportCamouflage;
use mirage_core::crypto::credential::subscriber_set::SubscriberSet;
use mirage_core::ids::MachineId;
use mirage_core::mirage::wire::Protocol;
use mirage_core::persona::{persona_for, Persona};
use mirage_node::core::registry::registry::Activation;
use tokio_util::sync::CancellationToken;

use mirage_standalone::artefact::{ArtefactMode, EntranceArtefact};
use mirage_standalone::box_runtime::BoxRuntime;
use mirage_standalone::chain::{ChainHop, ChainSpec};
use mirage_standalone::env::{discover_public_ipv4, ServerEnv};
use mirage_standalone::faces::{
    describe, propose, FaceProposal, HostPortDetector, PortDetector, PortState, Transport,
};
use mirage_standalone::identity::ServerIdentity;
use mirage_standalone::node::StandaloneNode;
use mirage_standalone::subscriber::{subscriber_set_path, write_subscriber_set};

/// The command succeeded.
const EXIT_OK: u8 = 0;
/// The command could not do what it was asked.
const EXIT_FAILURE: u8 = 1;

/// Where the box keeps its state.
const DEFAULT_DIR: &str = "/data";
/// Where the installer writes the box's configuration.
const DEFAULT_ENV_PATH: &str = "/opt/m1r4g3/server.env";
/// The file the face proposal is written to, inside the box's data directory.
const PROPOSAL_FILE: &str = "faces.proposed.toml";

/// Everything the CLI can refuse, by name.
#[derive(Debug)]
enum CliError {
    /// The command line itself was wrong.
    Usage(String),
    /// A file could not be read or written.
    Io {
        /// What was being done.
        action: String,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The configuration was refused.
    Config(String),
    /// The box has no address the customer could dial.
    NoPublicHost,
    /// The chain could not be built.
    Chain(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(msg) => write!(f, "usage: {msg}"),
            CliError::Io { action, source } => write!(f, "cannot {action}: {source}"),
            CliError::Config(msg) => write!(f, "configuration: {msg}"),
            CliError::NoPublicHost => write!(
                f,
                "the box has no public address: pass --host, set MIRAGE_PUBLIC_HOST, or give the box a routable address"
            ),
            CliError::Chain(msg) => write!(f, "chain: {msg}"),
        }
    }
}

impl std::error::Error for CliError {}

fn main() -> ExitCode {
    init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("m1r4g3-server: {err}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// Install the box's own log.
///
/// `RUST_LOG` decides what is printed; without it the box speaks at `info`.
/// A subscriber that cannot be installed is not fatal — the box still serves,
/// it just serves quietly, which is what it did before this existed.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}

/// Dispatch one command line.
fn run(args: &[String]) -> Result<u8, CliError> {
    let Some(command) = args.first() else {
        return Err(CliError::Usage(usage()));
    };
    // `env` takes a profile name, which the shared option parser would
    // refuse as an unknown flag. It is handled on its own, before that.
    if command == "env" {
        return cmd_env(&args[1..]);
    }
    let options = Options::parse(&args[1..])?;
    match command.as_str() {
        "init" => cmd_init(&options),
        "health" => cmd_health(&options),
        "propose" => cmd_propose(&options),
        "invite" => cmd_invite(&options),
        "revoke" => cmd_revoke(&options),
        "run" => cmd_run(&options),
        "prove-icmp" => cmd_prove_icmp(&options),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(EXIT_OK)
        }
        other => Err(CliError::Usage(format!("unknown command '{other}'\n{}", usage()))),
    }
}

/// The command line's usage text.
fn usage() -> String {
    "m1r4g3-server <command> [options]\n\
     \n\
     commands:\n\
     \x20 env\n\
     \x20         m1r4g3-server env all [--host NAME]\n\
     \x20         m1r4g3-server env quic [--host NAME]\n\
     \x20         m1r4g3-server env quic-mirage [--host NAME]\n\
     \x20         print a complete server.env for that profile and exit\n\
     \x20 init   --dir <path> [--env <path>] [--host <host>]\n\
     \x20         mint or load the box identity, sign the subscriber allowlist,\n\
     \x20         check that the chosen faces' ports are free on this box, write\n\
     \x20         client.link, and print that file's path\n\
     \x20 health --dir <path>\n\
     \x20         check that identity.json, subscriber.set and client.link are present and valid\n\
     \x20 propose --dir <path> [--format text|toml]\n\
     \x20         say what this box could publish — the free ports and the faces a\n\
     \x20         person is offered — and write faces.proposed.toml into the data dir\n\
     \x20 invite --dir <path> [--env <path>] [--host <host>] --name <name>\n\
     \x20         mint a guest's own key, admit it, and print that guest's\n\
     \x20         invitation — the artefact the guest may dial this box with\n\
     \x20 revoke --dir <path> --name <name>\n\
     \x20         take a guest's access away; the key stops being admitted\n\
     \x20 run    --dir <path> [--env <path>] [--host <host>]\n\
     \x20         build the control plane from the chain spec and serve the chain splice\n\
     \x20         until interrupted\n\
     \x20 prove-icmp --peer <ip> --id <u16>\n\
     \x20         open the ICMP door as a client, carry one HTTP/1.0 GET of\n\
     \x20         example.com through it, and print the byte count\n\
     \n\
     options:\n\
     \x20 --dir <path>    the box's data directory (default {DEFAULT_DIR})\n\
     \x20 --env <path>    the box's server.env (default {DEFAULT_ENV_PATH})\n\
     \x20 --host <host>   the address the customer dials (default: MIRAGE_PUBLIC_HOST,\n\
     \x20                 else the box's own IPv4 address)\n\
     \x20 --format <fmt>  how `propose` prints: text for a person (default), toml for\n\
     \x20                 the installer to read\n\
     \x20 --peer <ip>     ICMP peer, the server address the echo is sent to\n\
     \x20 --id <u16>      ICMP identifier of that door"
        .to_owned()
}

/// `env` — print one profile's `server.env` and nothing else.
///
/// `--host` defaults to `localhost`. It is the name written into SNI and
/// the other authority fields, not the box's public address. An unknown
/// profile is a usage error.
fn cmd_env(args: &[String]) -> Result<u8, CliError> {
    let mut profile_name: Option<String> = None;
    let mut host = String::from("localhost");
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--host" {
            index += 1;
            let value = args.get(index).ok_or_else(|| {
                CliError::Usage(format!("--host needs a value\n{}", usage()))
            })?;
            host = value.clone();
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown option '{arg}'\n{}",
                usage()
            )));
        }
        if profile_name.is_some() {
            return Err(CliError::Usage(format!(
                "unexpected argument '{arg}'\n{}",
                usage()
            )));
        }
        profile_name = Some(arg.to_owned());
        index += 1;
    }
    let Some(name) = profile_name else {
        return Err(CliError::Usage(usage()));
    };
    let Some(profile) = mirage_standalone::profile::parse_profile(&name) else {
        return Err(CliError::Usage(format!(
            "unknown profile '{name}'\n{}",
            usage()
        )));
    };
    print!("{}", mirage_standalone::profile::render(profile, &host));
    Ok(EXIT_OK)
}

/// How `propose` prints its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalFormat {
    /// One line per face, for a person to read.
    Text,
    /// The proposal file itself, for the installer to read.
    Toml,
}

/// The parsed options of one command.
struct Options {
    dir: PathBuf,
    env_path: PathBuf,
    host: Option<String>,
    format: ProposalFormat,
    /// The name of the subscriber a command is about.
    name: Option<String>,
    /// ICMP peer address for `prove-icmp`.
    peer: Option<String>,
    /// ICMP identifier for `prove-icmp`.
    icmp_id: Option<u16>,
}

impl Options {
    /// Parse `--key value` pairs.
    fn parse(args: &[String]) -> Result<Self, CliError> {
        let mut dir = PathBuf::from(DEFAULT_DIR);
        let mut env_path = PathBuf::from(DEFAULT_ENV_PATH);
        let mut host = None;
        let mut format = ProposalFormat::Text;
        let mut name = None;
        let mut peer = None;
        let mut icmp_id = None;
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].as_str();
            let mut take_value = |name: &str| -> Result<String, CliError> {
                index += 1;
                args.get(index)
                    .cloned()
                    .ok_or_else(|| CliError::Usage(format!("{name} needs a value")))
            };
            match arg {
                "--dir" => dir = PathBuf::from(take_value("--dir")?),
                "--env" => env_path = PathBuf::from(take_value("--env")?),
                "--host" => host = Some(take_value("--host")?),
                "--name" => name = Some(take_value("--name")?),
                "--peer" => peer = Some(take_value("--peer")?),
                "--id" => {
                    let raw = take_value("--id")?;
                    icmp_id = Some(raw.parse::<u16>().map_err(|_| {
                        CliError::Usage("--id needs a number".to_owned())
                    })?);
                }
                "--format" => {
                    let raw = take_value("--format")?;
                    format = match raw.trim() {
                        "text" => ProposalFormat::Text,
                        "toml" => ProposalFormat::Toml,
                        other => {
                            return Err(CliError::Usage(format!(
                                "unknown format '{other}' — use text or toml"
                            )))
                        }
                    }
                }
                other => {
                    return Err(CliError::Usage(format!(
                        "unknown option '{other}'\n{}",
                        usage()
                    )))
                }
            }
            index += 1;
        }
        Ok(Self {
            dir,
            env_path,
            host,
            format,
            name,
            peer,
            icmp_id,
        })
    }
}

/// `init` — prepare the box's state and hand the customer their artefact.
fn cmd_init(options: &Options) -> Result<u8, CliError> {
    // The environment is read FIRST: it may name the chain's mesh id, and the
    // box's own id is overridden by it — the boxes of one chain share one
    // mesh id, and the customer's link carries it.
    let env = load_env(&options.env_path)?;
    let identity = ServerIdentity::load_or_mint(&options.dir)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let identity = match env.chain.mesh_id.as_deref() {
        Some(mesh_id) => identity.with_mesh_id(mesh_id),
        None => identity,
    };
    let persona = box_persona(&identity)?;
    let faces = env
        .faces(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let endpoints = env
        .udp_endpoints(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let doors = env
        .protocol_doors(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let relays = env
        .relays(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let public_host = public_host(options, &env)?;

    // The doors the operator chose must actually be free ON THIS BOX. A
    // door on a port something else already holds would come up as a
    // listener that retries its bind forever while the box reports
    // healthy — so the refusal happens here, where the operator can still
    // be told which port it was.
    check_ports_free(&faces, &endpoints, &doors, &relays)?;

    ensure_subscriber_set(&options.dir, &identity)?;

    let link_path = EntranceArtefact::path_in(&options.dir);
    // The artefact carries every door this box publishes: the perimeter's
    // Mirage TCP faces, the node's Mirage UDP endpoints, and every other
    // protocol door.
    let published = mirage_standalone::env::published_faces(&faces, &endpoints, &doors);
    let written = ensure_client_link(&options.dir, &identity, &public_host, &published)?;
    if written {
        eprintln!("m1r4g3-server: wrote the client artefact");
    } else {
        eprintln!("m1r4g3-server: the client artefact is already there and still matches this box — left it alone");
    }

    // The path, and nothing else: the artefact itself is a secret.
    println!("{}", link_path.display());
    Ok(EXIT_OK)
}

/// `invite` — mint a guest key and print that guest's invitation.
///
/// The printed artefact is the invitation, and it carries the guest's own
/// key: whoever holds it may use this box, and nobody else. The box's own
/// key is untouched, so the owner keeps the access they had.
///
/// The artefact goes to stdout and nowhere else — it is a secret.
fn cmd_invite(options: &Options) -> Result<u8, CliError> {
    let Some(name) = options.name.as_deref() else {
        return Err(CliError::Usage("invite needs --name <name>".to_owned()));
    };
    let identity = ServerIdentity::load_or_mint(&options.dir)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let env = load_env(&options.env_path)?;
    let persona = box_persona(&identity)?;
    let faces = env
        .faces(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let endpoints = env
        .udp_endpoints(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let doors = env
        .protocol_doors(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let public_host = public_host(options, &env)?;
    let published = mirage_standalone::env::published_faces(&faces, &endpoints, &doors);

    let invitation = mirage_standalone::subscriber::issue_invitation(
        &options.dir,
        &identity,
        &public_host,
        &published,
        mirage_standalone::artefact::ArtefactMode::FullAuto,
        name,
        now_ms(),
    )
    .map_err(|e| CliError::Config(e.to_string()))?;

    let text = serde_json::to_string(&invitation.artefact)
        .map_err(|e| CliError::Config(format!("the invitation is not serialisable: {e}")))?;
    println!("{text}");
    Ok(EXIT_OK)
}

/// `revoke` — take a guest's access away.
///
/// The guest is named by `--name`, or by the subscription reference the
/// invitation carried. The record stays in the registry — the history is
/// worth keeping — but the signed allowlist is rebuilt without it, and the
/// running gate stops admitting that key at its next poll.
fn cmd_revoke(options: &Options) -> Result<u8, CliError> {
    let Some(target) = options.name.as_deref() else {
        return Err(CliError::Usage("revoke needs --name <name>".to_owned()));
    };
    let identity = ServerIdentity::load_or_mint(&options.dir)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let revocation = mirage_standalone::subscriber::revoke_subscriber(
        &options.dir,
        &identity,
        target,
        now_ms(),
    )
    .map_err(|e| CliError::Config(e.to_string()))?;
    println!(
        "revoked {} ({})",
        revocation.name, revocation.subscription_ref
    );
    Ok(EXIT_OK)
}

/// `propose` — say what this box could publish, and write it down.
///
/// The box answers a question it is good at — *which ports are free here* —
/// and offers a set of faces a person then chooses from. It does not choose:
/// nothing this command writes changes what the box publishes. That is
/// `server.env`'s job, and the operator's.
///
/// The proposal is written to `faces.proposed.toml` in the box's data
/// directory, which is the volume the installer reads over SSH, and printed
/// to stdout: as plain lines for a person, or as the file itself
/// (`--format toml`) for the installer.
fn cmd_propose(options: &Options) -> Result<u8, CliError> {
    // The box's own identity, so the masks carry the SAME hostname the box
    // will wear later: the name on the wire and the name in the artefact
    // must not disagree. Minting it here is the same minting `init` does.
    let identity = ServerIdentity::load_or_mint(&options.dir)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let persona = box_persona(&identity)?;

    let faces = propose(&HostPortDetector, &persona.hostname);
    let proposal = FaceProposal::from_faces(&faces)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let text = proposal
        .to_toml()
        .map_err(|e| CliError::Config(e.to_string()))?;

    let path = options.dir.join(PROPOSAL_FILE);
    fs::write(&path, &text).map_err(|e| CliError::Io {
        action: format!("write {}", path.display()),
        source: e,
    })?;

    match options.format {
        ProposalFormat::Text => {
            for line in describe(&faces) {
                println!("{line}");
            }
        }
        ProposalFormat::Toml => print!("{text}"),
    }
    Ok(EXIT_OK)
}

/// Check that every port the box's own faces name is free on this box.
///
/// A port that is **busy** is a refusal: the face cannot bind it, and the
/// operator has to hear which port it was before the box pretends to be up.
///
/// A port the detector **cannot judge** is NOT a refusal. There is no
/// `/proc/net` to read on some systems, and a privileged port cannot be
/// bound to test it without `CAP_NET_BIND_SERVICE`; refusing on a guess
/// would turn "I could not check" into "your box is broken". The check says
/// what it could not do, and carries on.
fn check_ports_free(
    faces: &[mirage_standalone::env::Face],
    endpoints: &[mirage_standalone::env::UdpEndpoint],
    doors: &[mirage_standalone::env::Face],
    relays: &[mirage_standalone::env::RelayDoor],
) -> Result<(), CliError> {
    let detector = HostPortDetector;
    for face in faces {
        let transport = if face.protocol.is_udp() {
            Transport::Udp
        } else {
            Transport::Tcp
        };
        check_one_port(&detector, face.port, transport, &face.id)?;
    }
    for endpoint in endpoints {
        check_one_port(&detector, endpoint.port, Transport::Udp, &endpoint.id)?;
    }
    for door in doors {
        // ICMP opens a raw socket. It does not bind a UDP port.
        if matches!(door.protocol, Protocol::Icmp { .. }) {
            continue;
        }
        let transport = if door.protocol.is_udp() {
            Transport::Udp
        } else {
            Transport::Tcp
        };
        check_one_port(&detector, door.port, transport, door.protocol.label())?;
    }
    for relay in relays {
        // ICMP opens a raw socket. It does not bind a UDP port.
        let transport = match relay.transport {
            mirage_standalone::env::RelayTransport::Tcp => Transport::Tcp,
            mirage_standalone::env::RelayTransport::Udp => Transport::Udp,
            mirage_standalone::env::RelayTransport::Icmp => continue,
        };
        check_one_port(&detector, relay.port, transport, &relay.id)?;
    }
    Ok(())
}

/// Check one port, and say what could not be checked.
fn check_one_port(
    detector: &dyn PortDetector,
    port: u16,
    transport: Transport,
    protocol: &str,
) -> Result<(), CliError> {
    match detector.state(port, transport) {
        PortState::Free => Ok(()),
        PortState::Taken => Err(CliError::Config(format!(
            "port {port} is already taken on this host — the face '{protocol}' cannot bind it"
        ))),
        PortState::Unknown => {
            eprintln!(
                "m1r4g3-server: could not verify that port {port} is free (no /proc/net to read, \
                 or not enough rights to bind it even to test it) — carrying on"
            );
            Ok(())
        }
    }
}

/// `health` — check the box's three files.
fn cmd_health(options: &Options) -> Result<u8, CliError> {
    let mut healthy = true;

    let identity = match ServerIdentity::load(&options.dir) {
        Ok(identity) => {
            println!("ok    identity.json");
            Some(identity)
        }
        Err(err) => {
            eprintln!("fail  identity.json: {err}");
            healthy = false;
            None
        }
    };

    match &identity {
        Some(identity) => {
            let path = subscriber_set_path(&options.dir);
            match mirage_subscriber_gate::subscriber_keys::load_subscriber_set_file(&path) {
                Ok(set) => match set.verify(&identity.subscriber_issuer_verifying_key()) {
                    Ok(_) => println!("ok    subscriber.set"),
                    Err(err) => {
                        eprintln!("fail  subscriber.set: {err}");
                        healthy = false;
                    }
                },
                Err(err) => {
                    eprintln!("fail  subscriber.set: {err}");
                    healthy = false;
                }
            }
        }
        None => {
            eprintln!("fail  subscriber.set: not checked — the box identity did not load");
            healthy = false;
        }
    }

    match &identity {
        Some(identity) => match check_client_link(&options.dir, identity) {
            Ok(()) => println!("ok    client.link"),
            Err(reason) => {
                eprintln!("fail  client.link: {reason}");
                healthy = false;
            }
        },
        None => {
            eprintln!("fail  client.link: not checked — the box identity did not load");
            healthy = false;
        }
    }

    Ok(if healthy { EXIT_OK } else { EXIT_FAILURE })
}

/// Where this box stands in the chain it was told about.
///
/// The three shapes are told apart by the CONFIGURATION, not by the shape of
/// the chain — a box that stands alone and a box that is hop 0 of somebody
/// else's chain are both "the only hop of a one-hop chain", and they do the
/// opposite things with their faces:
///
/// * **Alone** — no chain was named. The box serves the customer on its faces
///   and exits from itself. It holds no chain listener: nobody dials a box
///   that stands alone as a hop.
/// * **Edge** — the whole chain was named, but no place in it. The box owns
///   the chain and dials it; the customer's session rides the chain.
/// * **Hop** — a place among the chain's hops was named. The box serves the
///   chain on its faces and no customer at all.
enum Placement {
    /// Stands alone: it serves the customer and is its own exit.
    Alone,
    /// The edge of a chain it owns: it serves the customer and dials the chain.
    Edge,
    /// A hop of a chain someone else owns: it serves the chain.
    Hop(usize),
}

/// `run` — build the control plane, and say what is missing.
/// `run` — serve the box's data plane.
///
/// The box is a node without a monitor: its identity comes from the local
/// directory, its chain from the local configuration, and the three objects a
/// fleet node receives over the monitor's control channel — the listener
/// spec, the peer table and the chain bindings — are built locally, from the
/// box's own keys.
fn cmd_run(options: &Options) -> Result<u8, CliError> {
    // Two boxes in one guest each get their own chain sockets. The fleet
    // leaves this unset and keeps `/run/mirage/...`.
    mirage_core::local_endpoint::set_runtime_root(options.dir.join("run"));
    // The environment is read FIRST: it may name the chain's mesh id, and the
    // box's own id is overridden by it — the boxes of one chain share one
    // mesh id, and the customer's link carries it.
    let env = load_env(&options.env_path)?;
    let identity = ServerIdentity::load_or_mint(&options.dir)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let identity = match env.chain.mesh_id.as_deref() {
        Some(mesh_id) => identity.with_mesh_id(mesh_id),
        None => identity,
    };
    let persona = box_persona(&identity)?;
    let faces = env
        .faces(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    // The node's own UDP endpoints — the ports the NODE binds, wearing a
    // real UDP mask. They are not perimeter faces: the perimeter refuses
    // every UDP camouflage but its own datagram door.
    let endpoints = env
        .udp_endpoints(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let doors = env
        .protocol_doors(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let relays = env
        .relays(&persona)
        .map_err(|e| CliError::Config(e.to_string()))?;
    let public_host = public_host(options, &env)?;
    check_ports_free(&faces, &endpoints, &doors, &relays)?;

    // A hop's chain listener wears the first Mirage TCP face. A box that
    // publishes only protocol doors still needs an address on its own hop
    // row; that address is the first door, and the chain mask stays none.
    let (listen_port, camouflage) = if let Some(face) = faces.first() {
        let mask = face.protocol.to_mask(face.port).map_err(CliError::Config)?;
        (face.port, Some(mask))
    } else {
        let port = doors
            .first()
            .map(|door| door.port)
            .or_else(|| endpoints.first().map(|endpoint| endpoint.port))
            .or_else(|| relays.first().map(|relay| relay.port))
            .ok_or_else(|| {
                CliError::Config(
                    "server.env: no door — the box publishes nothing a subscriber can dial"
                        .to_owned(),
                )
            })?;
        (port, Some(TransportCamouflage::None))
    };

    let local = ChainHop {
        addr: format!("{}:{}", public_host, listen_port),
        public_key: Some(identity.node_wire_pubkey_hex()),
        node_id: None,
        role: match env.chain.role {
            mirage_standalone::env::ChainRole::Exit => mirage_core::config::HopRole::Exit,
            mirage_standalone::env::ChainRole::Middle => mirage_core::config::HopRole::Middle,
            mirage_standalone::env::ChainRole::Entry => mirage_core::config::HopRole::Entry,
            // The edge has no row of its own — it is not a hop of its chain —
            // so this role is never read for it.
            mirage_standalone::env::ChainRole::Edge => mirage_core::config::HopRole::Exit,
        },
        camouflage,
        // The box's own datagram door — where this box answers the chain's
        // datagram-native leg. Set only when the configuration named a port
        // for it; a box without one carries TCP only.
        udp_addr: env
            .chain
            .udp_port
            .map(|port| format!("{}:{}", public_host, port)),
    };
    // When the configuration named the WHOLE chain, this box knows every hop
    // and where it stands among them. That is what lets the exit box accept
    // the entry box's leg: the short description only tells a box about the
    // hop AFTER it, and never about the one in front.
    //
    // The chain's own shape decides what this box is:
    //
    // * a position in the chain — this box is a HOP of it, and it serves the
    //   chain's listener on its own faces;
    // * no position, but the whole chain named — this box is the chain's
    //   EDGE: it owns the chain and dials it, and it serves no chain
    //   listener of its own;
    // * neither — the short description: the box stands alone, and it is its
    //   own exit.
    //
    // The third case is NOT the first case with the number zero. A box that
    // stands alone serves the CUSTOMER on its faces and exits from itself; a
    // box that is hop 0 of somebody else's chain serves the CHAIN on its
    // faces and no customer at all. The two look alike in the chain's shape
    // — both are the only hop of a one-hop chain — and only the
    // configuration tells them apart. So the placement is decided HERE, once,
    // and everything downstream reads it.
    let (chain, placement) = match (env.chain.position, env.chain.length) {
        (Some(position), _) => {
            let chain = ChainSpec::from_env_full(&env.chain, local)
                .map_err(|e| CliError::Chain(e.to_string()))?;
            (chain, Placement::Hop(position))
        }
        (None, Some(_)) => {
            let chain = ChainSpec::from_env_full(&env.chain, local)
                .map_err(|e| CliError::Chain(e.to_string()))?;
            (chain, Placement::Edge)
        }
        (None, None) => {
            let chain = ChainSpec::from_env(&env.chain, local)
                .map_err(|e| CliError::Chain(e.to_string()))?;
            (chain, Placement::Alone)
        }
    };
    // Where this box stands among the chain's hops — `None` for a box that is
    // not a hop of it: the edge owns the chain, and a box that stands alone
    // is its own exit.
    let local_index = match placement {
        Placement::Hop(position) => Some(position),
        Placement::Edge | Placement::Alone => None,
    };

    // The operator key the node's gate verifies a leg's signature against.
    //
    // The chain's key is the chain's trust: every box of the chain knows its
    // public half, and the hop that receives a leg checks the leg against it.
    // A box with no chain — one that stands alone — is its own operator, and
    // pins its own key.
    let operator_pubkey = env
        .chain
        .operator_pubkey_hex
        .clone()
        .unwrap_or_else(|| identity.operator_pubkey_hex());
    std::env::set_var(
        mirage_node::core::bootstrap::OPERATOR_PUBKEY_ENV,
        operator_pubkey,
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Config(format!("the async runtime could not be started: {e}")))?;

    runtime.block_on(async move {
        let node = StandaloneNode::build(&identity, &chain, local_index, &faces, env.dns.as_deref())
            .map_err(|e| CliError::Config(e.to_string()))?;

        // The chain's leg — the edge's way into the chain it owns. Only the
        // edge has one: a hop receives legs, it does not send them, and a box
        // that stands alone has no chain to walk — it IS the exit.
        let chain_leg = match placement {
            Placement::Hop(_) => None,
            Placement::Alone => None,
            Placement::Edge => {
                let secret = env.chain.operator_secret_hex.as_deref().ok_or_else(|| {
                    CliError::Config(
                        "the box owns a chain but holds no chain operator key — the chain cannot be walked"
                            .to_owned(),
                    )
                })?;
                let mesh_id = env.chain.mesh_id.as_deref().ok_or_else(|| {
                    CliError::Config(
                        "the box owns a chain but holds no chain mesh id — the chain's legs would be refused"
                            .to_owned(),
                    )
                })?;
                let slice = mirage_core::capsule::RoleSlice {
                    role: mirage_core::identity::ServiceRole::Edge,
                    wire_privkey: identity.node_wire().secret.to_bytes(),
                    signing_privkey: None,
                    wire_pubkey_hex: identity.node_wire_pubkey_hex(),
                    signing_pubkey_hex: None,
                };
                Some(Arc::new(
                    mirage_standalone::chain_leg::ChainLeg::build(
                        &chain,
                        node.control_plane().peer_table.clone(),
                        mesh_id,
                        secret,
                        slice,
                    )
                    .map_err(|e| CliError::Config(e.to_string()))?,
                ))
            }
        };

        let control_plane = node.control_plane();
        println!("chain id      : {}", chain.chain_id);
        println!(
            "chain role    : {}",
            match placement {
                Placement::Alone => "alone — this box is its own exit".to_owned(),
                Placement::Edge => "edge — this box owns the chain and dials it".to_owned(),
                Placement::Hop(position) => format!(
                    "hop {position} — role={}",
                    chain
                        .hops
                        .get(position)
                        .map(|hop| format!("{:?}", hop.role))
                        .unwrap_or_else(|| "unknown".to_owned())
                ),
            }
        );
        match placement {
            Placement::Hop(position) => {
                println!("chain position: {position} of {}", chain.hops.len());
            }
            Placement::Edge => println!(
                "chain position: edge of {} hop(s)",
                chain.hops.len()
            ),
            Placement::Alone => println!("chain position: alone — there is no chain to walk"),
        }
        println!("hops          : {}", chain.hops.len());
        for (index, hop) in chain.hops.iter().enumerate() {
            println!(
                "  hop {index}      : {}  role={:?}",
                hop.addr, hop.role
            );
        }
        println!(
            "peer table    : {} peer(s)",
            control_plane.peer_table.peers.len()
        );
        if let Some(binding) = control_plane.chain_bindings.bindings.first() {
            println!(
                "chain binding : mesh={} chain={} legs={} exit={}",
                binding.mesh_id,
                binding.chain_id,
                binding.legs.len(),
                binding.exit.node_id
            );
        }
        match control_plane.listener_spec.as_ref() {
            Some(spec) => {
                println!("listener id   : {}", spec.id);
                println!("fingerprint   : {}", hex::encode(spec.fingerprint.0));
            }
            None => println!(
                "listener id   : none — {}",
                match placement {
                    Placement::Alone => "this box stands alone and is its own exit",
                    Placement::Edge => "this box owns the chain and dials it",
                    Placement::Hop(_) => "this box serves the chain",
                }
            ),
        }
        match control_plane.datagram_listener_spec.as_ref() {
            Some(spec) => {
                println!("datagram id   : {}", spec.id);
                if let Some(door) = local_index
                    .and_then(|index| chain.hops.get(index))
                    .and_then(|hop| hop.udp_addr.clone())
                {
                    println!("datagram door : {door}");
                }
            }
            None => println!(
                "datagram id   : none — {}",
                match placement {
                    Placement::Alone => "this box stands alone and exits from itself",
                    Placement::Edge => "this box serves no chain listener — it dials the chain's datagram leg",
                    Placement::Hop(_) => "this hop has no datagram door — the chain carries TCP only here",
                }
            ),
        }
        // The datagram chain this box knows about: its own id and the doors it
        // walks. On the edge those are the doors it dials; on a hop — the door
        // it serves and the one it hands the datagram to.
        if chain.hops.iter().any(|hop| hop.udp_addr.is_some()) {
            println!(
                "datagram chain: {} (a chain of its own — the datagram leg speaks UDP)",
                chain.datagram_chain_id()
            );
            for hop in &chain.hops {
                if let Some(door) = &hop.udp_addr {
                    println!("datagram hop  : {door}");
                }
            }
        }
        if endpoints.is_empty() {
            println!("udp endpoints : none");
        } else {
            println!("udp endpoints : {} (held by the node)", endpoints.len());
            for endpoint in &endpoints {
                println!(
                    "  udp {}      : {}  protocol={}",
                    endpoint.port,
                    endpoint.id,
                    endpoint.protocol.label()
                );
            }
        }
        if doors.is_empty() {
            println!("protocol doors: none");
        } else {
            println!("protocol doors: {}", doors.len());
            for door in &doors {
                println!(
                    "  door {}     : {}  protocol={}",
                    door.port, door.id, door.protocol.label()
                );
            }
        }
        if relays.is_empty() {
            println!("relays        : none");
        } else {
            println!("relays        : {}", relays.len());
            for relay in &relays {
                let via = match relay.transport {
                    mirage_standalone::env::RelayTransport::Tcp => "tcp",
                    mirage_standalone::env::RelayTransport::Udp => "udp",
                    mirage_standalone::env::RelayTransport::Icmp => "icmp",
                };
                println!(
                    "  relay {}    : {}  transport={via}",
                    relay.port, relay.id
                );
            }
        }

        // The registry recomputes the fingerprint and refuses a spec that
        // does not match — so this is the box's own check that the spec it
        // built is the spec the node reads.
        //
        // The edge has no spec to activate: it serves no chain listener.
        let activation = node
            .activate()
            .await
            .map_err(|e| CliError::Config(e.to_string()))?;
        println!(
            "activation    : {}",
            match &activation {
                Some(Activation::Bound(addr)) => format!("bound at {addr}"),
                Some(Activation::Registered(id)) => format!("registered as {id}"),
                None => format!(
                    "none — {}",
                    match placement {
                        Placement::Alone => "this box stands alone and is its own exit",
                        Placement::Edge => "this box owns the chain and dials it",
                        Placement::Hop(_) => "this box serves the chain",
                    }
                ),
            }
        );
        println!();

        // The box itself: the perimeter on the faces, the client entrance
        // behind it, the box's own exit behind that — or the chain, when the
        // box owns one.
        let box_runtime = BoxRuntime::build(
            &identity,
            node,
            &faces,
            &endpoints,
            &doors,
            &relays,
            subscriber_set_path(&options.dir),
            env.exit_country.as_deref(),
            env.allow_private_exit_targets,
            chain_leg,
            // The port this box answers the chain's DATAGRAM leg on. Only a
            // hop has one: the edge dials out, and a solo box has no chain.
            env.chain.udp_port,
        )
        .map_err(|e| CliError::Config(e.to_string()))?;
        println!("faces         : {}", faces.len());
        for face in &faces {
            println!(
                "  face {}      : {}  protocol={}",
                face.port,
                face.id,
                face.protocol.label()
            );
        }
        println!(
            "exit country  : {}",
            env.exit_country
                .as_deref()
                .map(|c| c.to_owned())
                .unwrap_or_else(|| "unnamed — the auto exit only".to_owned())
        );
        println!();

        eprintln!(
            "m1r4g3-server: serving — the perimeter holds the faces, the client entrance holds the subscribers."
        );

        let cancel = CancellationToken::new();
        let interrupt = cancel.clone();
        tokio::spawn(async move {
            if let Err(err) = tokio::signal::ctrl_c().await {
                eprintln!("m1r4g3-server: the interrupt handler failed: {err}");
                return;
            }
            interrupt.cancel();
        });

        box_runtime
            .serve(cancel)
            .await
            .map_err(|e| CliError::Config(e.to_string()))?;
        Ok(EXIT_OK)
    })
}

/// Dial the ICMP door at `--peer` / `--id` and carry one GET of example.com.
///
/// Prints `icmp prove: bytes=N http=CODE example=yes|no`. Exit 0 only when
/// the body contains the example.com mark. No key material is printed.
fn cmd_prove_icmp(options: &Options) -> Result<u8, CliError> {
    let peer = options.peer.as_deref().ok_or_else(|| {
        CliError::Usage("prove-icmp needs --peer <ip>".to_owned())
    })?;
    let peer: std::net::IpAddr = peer
        .parse()
        .map_err(|_| CliError::Usage("prove-icmp --peer is not an IP address".to_owned()))?;
    let identifier = options.icmp_id.ok_or_else(|| {
        CliError::Usage("prove-icmp needs --id <u16>".to_owned())
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Config(format!("the async runtime could not be started: {e}")))?;
    runtime.block_on(async move {
        use mirage_protocol::camouflage::UdpCamouflageLayer;
        use mirage_protocol::preamble::write_preamble;
        use mirage_protocol::protocols::l3::icmp::IcmpCamouflage;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let layer = IcmpCamouflage::new(peer, identifier, 1400);
        let mut stream = layer
            .connect_client(std::net::SocketAddr::new(peer, 0), "")
            .await
            .map_err(|e| CliError::Config(format!("icmp door did not open: {e}")))?;
        write_preamble(&mut stream, "example.com", 80)
            .await
            .map_err(|e| CliError::Config(format!("icmp preamble was refused: {e}")))?;
        stream
            .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| CliError::Config(format!("icmp write failed: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| CliError::Config(format!("icmp write failed: {e}")))?;
        let mut body = Vec::new();
        let mut buf = [0u8; 2048];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        while body.len() < 8192 && tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => body.extend_from_slice(&buf[..n]),
            }
            if body.windows(14).any(|window| window == b"Example Domain") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&body);
        let code = text.split_whitespace().nth(1).unwrap_or("none");
        let example = body.windows(14).any(|window| window == b"Example Domain");
        println!(
            "icmp prove: bytes={} http={code} example={}",
            body.len(),
            if example { "yes" } else { "no" }
        );
        if example {
            Ok(EXIT_OK)
        } else {
            Ok(EXIT_FAILURE)
        }
    })
}

/// Read `server.env`, falling back to an empty configuration when the file is
/// not there.
fn load_env(path: &Path) -> Result<ServerEnv, CliError> {
    match fs::read_to_string(path) {
        Ok(text) => ServerEnv::parse(&text).map_err(|e| CliError::Config(e.to_string())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "m1r4g3-server: no configuration at {} — using the defaults",
                path.display()
            );
            Ok(ServerEnv::parse("").expect("an empty configuration parses"))
        }
        Err(source) => Err(CliError::Io {
            action: format!("read {}", path.display()),
            source,
        }),
    }
}

/// The address the customer dials.
fn public_host(options: &Options, env: &ServerEnv) -> Result<String, CliError> {
    if let Some(host) = options.host.as_ref() {
        if !host.trim().is_empty() {
            return Ok(host.trim().to_owned());
        }
    }
    if let Some(host) = env.public_host.as_ref() {
        if !host.trim().is_empty() {
            return Ok(host.trim().to_owned());
        }
    }
    discover_public_ipv4()
        .map(|ip| ip.to_string())
        .ok_or(CliError::NoPublicHost)
}

/// The persona this box wears.
fn box_persona(identity: &ServerIdentity) -> Result<Persona, CliError> {
    let machine = MachineId::new(identity.mesh_id())
        .map_err(|e| CliError::Config(format!("the box identity is unusable: {e}")))?;
    Ok(persona_for(&machine))
}

/// Write the subscriber allowlist, unless a valid one is already there.
///
/// The file is left alone when it still verifies against this box's own
/// issuer key and still names this box's subscriber. That keeps `init`
/// idempotent: a restart does not silently extend the subscription, and the
/// file the box serves does not change under the customer's feet.
fn ensure_subscriber_set(dir: &Path, identity: &ServerIdentity) -> Result<bool, CliError> {
    let path = subscriber_set_path(dir);
    if let Ok(raw) = fs::read(&path) {
        if let Ok(set) = SubscriberSet::decode(&raw) {
            if set.verify(&identity.subscriber_issuer_verifying_key()).is_ok()
                && set
                    .entries
                    .iter()
                    .any(|entry| entry.device_pubkey_hex == identity.subscriber_pubkey_hex())
            {
                return Ok(false);
            }
        }
    }
    write_subscriber_set(dir, identity, now_ms()).map_err(|e| CliError::Config(e.to_string()))?;
    Ok(true)
}

/// Write the client artefact, unless a matching one is already there.
///
/// A matching artefact — same box, same subscriber key, same version — is
/// left exactly as it is. The file is what the customer already holds, and
/// re-issuing it would change `issued_at_ms` for no reason: the installer
/// reads it once, and a stable file is one less thing that changes under a
/// running installation.
fn ensure_client_link(
    dir: &Path,
    identity: &ServerIdentity,
    public_host: &str,
    faces: &[mirage_standalone::env::Face],
) -> Result<bool, CliError> {
    let path = EntranceArtefact::path_in(dir);
    if let Ok(raw) = fs::read(&path) {
        if let Ok(text) = std::str::from_utf8(&raw) {
            if let Ok(artefact) = serde_json::from_str::<EntranceArtefact>(text) {
                if artefact.v == mirage_standalone::artefact::CURRENT_VERSION
                    && artefact.mesh_id == identity.mesh_id()
                    && artefact.private_key_hex == identity.subscriber_secret_hex()
                    && !artefact.entrances.is_empty()
                {
                    return Ok(false);
                }
            }
        }
    }
    let artefact = EntranceArtefact::build(
        identity,
        public_host,
        faces,
        ArtefactMode::FullAuto,
        "standalone",
        now_ms(),
    )
    .map_err(|e| CliError::Config(e.to_string()))?;
    EntranceArtefact::write_client_link(dir, &artefact)
        .map_err(|e| CliError::Config(e.to_string()))?;
    Ok(true)
}

/// Check that the artefact on disk is one this box can stand behind.
fn check_client_link(dir: &Path, identity: &ServerIdentity) -> Result<(), String> {
    let path = EntranceArtefact::path_in(dir);
    let raw = fs::read(&path).map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(&raw).map_err(|_| "the file is not UTF-8".to_owned())?;
    if text.lines().count() != 1 {
        return Err("the file is not one line".to_owned());
    }
    let artefact: EntranceArtefact =
        serde_json::from_str(text).map_err(|e| format!("it is not a valid artefact: {e}"))?;
    if artefact.v != mirage_standalone::artefact::CURRENT_VERSION {
        return Err(format!("unsupported artefact version {}", artefact.v));
    }
    if artefact.mesh_id != identity.mesh_id() {
        return Err("it belongs to another box".to_owned());
    }
    if artefact.private_key_hex != identity.subscriber_secret_hex() {
        return Err("it carries another subscriber key".to_owned());
    }
    if artefact.entrances.is_empty() {
        return Err("it has no faces".to_owned());
    }
    Ok(())
}

/// Milliseconds since the epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
