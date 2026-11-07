//! The plane wire, end to end, over a memory tunnel.
//!
//! The box's side of the packet plane: the hello comes in, the welcome goes
//! out, and the welcome names the address the client owns. The packets
//! themselves need a TUN device, which a test cannot have -- the address book
//! is a trait exactly so that this test can stand in for it.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mirage_control_plane::edge_session::ClientAssignment;
use mirage_control_plane::{
    EdgeHello, EdgeOutcome, EdgeRefusal, EdgeWelcome, ExitPreference,
};
use mirage_core::error::MirageError;
use mirage_protocol::plane::PacketPlane;
use mirage_protocol::traits::Tunnel;
use mirage_vpn::ip_plane::{AddressBook, TUN_PREFIX};
use mirage_vpn::plane::serve_plane_session;
use mirage_vpn::testing::MemoryTunnel;
use tokio::sync::Notify;

/// A plane that carries no packet: this test is about the handshake.
///
/// The session waits for packets that never come, so the test ends the
/// session by closing the plane.
struct QuietPlane {
    closed: AtomicBool,
    notify: Notify,
}

impl QuietPlane {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    /// End the session: the packet loop sees the closure and returns.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn wait_closed(&self) {
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            self.notify.notified().await;
        }
    }
}

#[async_trait::async_trait]
impl PacketPlane for QuietPlane {
    async fn send_packet(&self, _packet: &[u8]) -> Result<(), MirageError> {
        Ok(())
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> Result<usize, MirageError> {
        self.wait_closed().await;
        Err(MirageError::TunnelClosed)
    }

    fn max_packet_size(&self) -> usize {
        1280
    }
}

/// An address book with one address in it.
struct OneAddress {
    addr: Ipv4Addr,
    taken: Mutex<bool>,
    registered: Mutex<Vec<Ipv4Addr>>,
    released: Mutex<Vec<Ipv4Addr>>,
    /// The bell that ends the packet loop.
    finished: Notify,
}

impl OneAddress {
    fn new(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            taken: Mutex::new(false),
            registered: Mutex::new(Vec::new()),
            released: Mutex::new(Vec::new()),
            finished: Notify::new(),
        }
    }

    /// End the session: the packet loop returns, and the session is over.
    fn finish(&self) {
        self.finished.notify_waiters();
    }
}

#[async_trait::async_trait]
impl AddressBook for OneAddress {
    fn assign(&self) -> Option<Ipv4Addr> {
        let mut taken = self.taken.lock().expect("the lock");
        if *taken {
            return None;
        }
        *taken = true;
        Some(self.addr)
    }

    fn release(&self, addr: Ipv4Addr) {
        *self.taken.lock().expect("the lock") = false;
        self.released.lock().expect("the lock").push(addr);
    }

    fn register_peer(&self, address: Ipv4Addr, _plane: Arc<dyn PacketPlane>) {
        self.registered.lock().expect("the lock").push(address);
    }

    async fn serve_peer(self: Arc<Self>, _plane: Arc<dyn PacketPlane>, _assigned: Option<Ipv4Addr>) {
        // The packet loop. The test ends it when the session is over.
        self.finished.notified().await;
    }
}

/// Read the welcome the box sends.
async fn read_welcome(tunnel: &mut Box<dyn Tunnel>) -> EdgeWelcome {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match EdgeWelcome::decode(&buf) {
            Ok((welcome, _consumed)) => return welcome,
            Err(mirage_control_plane::EdgeSessionError::Truncated { .. }) => {}
            Err(other) => panic!("the welcome is malformed: {other}"),
        }
        let count = tunnel.recv(&mut chunk).await.expect("a read");
        assert_ne!(count, 0, "the box closed the session before the welcome");
        buf.extend_from_slice(&chunk[..count]);
    }
}

/// The box answers a version-4 hello with the address the client owns.
#[tokio::test]
async fn the_plane_answers_a_version_four_hello_with_the_assigned_address() {
    let (client, server) = MemoryTunnel::pair();
    let book = Arc::new(OneAddress::new(Ipv4Addr::new(10, 77, 0, 2)));
    let plane = Arc::new(QuietPlane::new());

    let served = tokio::spawn(serve_plane_session(
        server,
        Arc::clone(&plane) as Arc<dyn PacketPlane>,
        Arc::clone(&book) as Arc<dyn AddressBook>,
        Some(41443),
    ));

    let mut client = client;
    let hello = EdgeHello {
        version: 4,
        exit: ExitPreference::Auto,
        flags: EdgeHello::FLAG_ACCEPTS_ASSIGNMENT,
        offered_ports: Vec::new(),
    };
    client
        .send(&hello.encode().expect("the hello"))
        .await
        .expect("the hello goes out");

    let welcome = read_welcome(&mut client).await;
    assert_eq!(welcome.version, 4);
    assert_eq!(
        welcome.outcome,
        EdgeOutcome::Accepted {
            exit: ExitPreference::Auto
        }
    );
    assert_eq!(welcome.assigned_face_port, Some(41443));
    // The plane carries whole IP packets: the flag says so.
    assert_eq!(welcome.carries_datagrams, Some(true));
    assert_eq!(
        welcome.assigned_client,
        Some(ClientAssignment {
            addr: Ipv4Addr::new(10, 77, 0, 2),
            prefix: TUN_PREFIX,
        })
    );
    // The peer owns its address from the moment it joins.
    assert_eq!(
        book.registered.lock().expect("the lock").as_slice(),
        &[Ipv4Addr::new(10, 77, 0, 2)]
    );

    plane.close();
    served.abort();
}

/// The address goes back to the pool when the session ends.
#[tokio::test]
async fn the_address_goes_back_to_the_pool_when_the_session_ends() {
    let (client, server) = MemoryTunnel::pair();
    let book = Arc::new(OneAddress::new(Ipv4Addr::new(10, 77, 0, 3)));
    let plane = Arc::new(QuietPlane::new());

    let served = tokio::spawn(serve_plane_session(
        server,
        Arc::clone(&plane) as Arc<dyn PacketPlane>,
        Arc::clone(&book) as Arc<dyn AddressBook>,
        Some(41443),
    ));

    let mut client = client;
    let hello = EdgeHello {
        version: 4,
        exit: ExitPreference::Auto,
        flags: EdgeHello::FLAG_ACCEPTS_ASSIGNMENT,
        offered_ports: Vec::new(),
    };
    client
        .send(&hello.encode().expect("the hello"))
        .await
        .expect("the hello goes out");
    let _welcome = read_welcome(&mut client).await;

    book.finish();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), served).await;

    assert_eq!(
        book.released.lock().expect("the lock").as_slice(),
        &[Ipv4Addr::new(10, 77, 0, 3)]
    );
}

/// A peer that offers an older version is refused by name.
#[tokio::test]
async fn an_older_version_is_refused_by_name() {
    let (client, server) = MemoryTunnel::pair();
    let book = Arc::new(OneAddress::new(Ipv4Addr::new(10, 77, 0, 4)));
    let plane = Arc::new(QuietPlane::new());

    let served = tokio::spawn(serve_plane_session(
        server,
        Arc::clone(&plane) as Arc<dyn PacketPlane>,
        Arc::clone(&book) as Arc<dyn AddressBook>,
        Some(41443),
    ));

    let mut client = client;
    let hello = EdgeHello {
        version: 3,
        exit: ExitPreference::Auto,
        flags: 0,
        offered_ports: vec![41443],
    };
    client
        .send(&hello.encode().expect("the hello"))
        .await
        .expect("the hello goes out");

    let welcome = read_welcome(&mut client).await;
    // A refusal carries no session, so it is answered in the oldest shape:
    // no port, no address, no flag.
    assert_eq!(welcome.version, 1);
    assert_eq!(
        welcome.outcome,
        EdgeOutcome::Refused(EdgeRefusal::UnsupportedVersion {
            requested: 3,
            supported: 4,
        })
    );
    assert_eq!(welcome.assigned_face_port, None);
    assert_eq!(welcome.assigned_client, None);
    assert_eq!(welcome.carries_datagrams, None);
    // A refused peer gets no address.
    assert!(book.registered.lock().expect("the lock").is_empty());

    served.abort();
}
