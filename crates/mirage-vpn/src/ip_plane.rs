//! The box's L3 exit: the TUN device and the peers behind it.
//!
//! # What this is
//!
//! The client sends WHOLE IP PACKETS inside QUIC datagrams. The box speaks no
//! protocol of its own -- no TCP, no UDP, no ICMP: it is an **L3 forwarder**.
//! The packets go into the box's own TUN device, the kernel routes them (and
//! masquerades them) to the internet, and the replies come back through the
//! same device.
//!
//! ```text
//!   the client                  the box                      the internet
//!     |  datagram: an IP packet    |                             |
//!     | ------------------------> |  write into the tun        |
//!     |                           |  the kernel routes it   -->|
//!     |                           |                             |
//!     |  datagram: an IP packet    |  the tun gives it back     |
//!     | <------------------------ |  the peer map routes it    |
//! ```
//!
//! # The peer map
//!
//! A packet that arrives FROM a peer teaches the box that peer's address --
//! the source of the packet. A packet that comes FROM THE TUN is routed back
//! by its destination: the map says which peer owns it. A destination nobody
//! owns is dropped and counted.
//!
//! Both families are carried: IPv4 and IPv6. A peer owns an address in each
//! of them, and the rule that gives a client its address is the same on both
//! ends of the tunnel -- the host number of the IPv4 address becomes the host
//! number of the IPv6 address, so the two ends never have to be told about
//! each other.
//!
//! The address of a peer is ASSIGNED, not only learned: when a peer joins,
//! the box hands it an address of the client network and puts it into the
//! map right away, so the first reply finds its way home even before the
//! peer sends a packet of its own. The assigned address is authoritative --
//! a packet from any other address is dropped and counted.
//!
//! # The platform
//!
//! The TUN device is a Linux thing. The crate is also built on Windows, where
//! [`IpPlane::open`] refuses with a clear error and the rest of the VPN keeps
//! working.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use mirage_protocol::plane::{PacketPlane, MAX_PACKET_SIZE};
use tokio::sync::mpsc;

mod device;

// -----------------------------------------------------------------------------
// The configuration
// -----------------------------------------------------------------------------

/// The name of the box's TUN device.
pub const TUN_NAME: &str = "mgt0";

/// The address of the box's TUN device.
pub const TUN_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 254);

/// The prefix length of the client network.
pub const TUN_PREFIX: u8 = 24;

/// The network the clients live in.
pub const CLIENT_NETWORK: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 0);

/// The first address the box hands out to a client.
///
/// The box's own address ([`TUN_ADDRESS`]) and the network address are not
/// clients' -- the pool starts right after them.
pub const CLIENT_POOL_FIRST: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

/// The last address the box hands out to a client.
pub const CLIENT_POOL_LAST: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 253);

/// The MTU of the box's TUN device.
///
/// 1280 is the size of the biggest packet the plane carries: the packet that
/// goes in and the packet that comes out are the same size, so nothing is
/// ever split.
pub const TUN_MTU: u16 = 1280;

/// The box's own IPv6 address on the TUN device.
///
/// The client IPv6 network is `fd77::/64`. The box is its last host, the
/// clients are the others.
pub const TUN_ADDRESS_V6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 254);

/// The prefix of the client IPv6 network.
pub const TUN_PREFIX_V6: u8 = 64;

/// The client IPv6 network.
pub const CLIENT_NETWORK_V6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 0);

/// The IPv6 address of the peer that owns this IPv4 address.
///
/// The rule is the same on both ends of the tunnel: the host number of the
/// IPv4 address becomes the host number of the client IPv6 network. The
/// client derives its own IPv6 address the same way, so the two never have
/// to be told about each other.
pub fn derive_client_v6(v4: Ipv4Addr) -> Ipv6Addr {
    Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, u16::from(v4.octets()[3]))
}

/// The smallest an IPv4 header can be: twenty bytes.
const MIN_IPV4_HEADER: usize = 20;

/// The smallest an IPv6 header can be: forty bytes.
const MIN_IPV6_HEADER: usize = 40;

/// The biggest datagram the plane reads: an IP packet is at most this big.
const DATAGRAM_BUFFER: usize = 65535;

/// How the box's IP plane is set up.
#[derive(Debug, Clone)]
pub struct IpPlaneConfig {
    /// The name of the TUN device.
    pub interface: String,
    /// The address of the TUN device.
    pub address: Ipv4Addr,
    /// The prefix length of the client network.
    pub prefix: u8,
    /// The network the clients live in -- the NAT rule is written for it.
    pub network: Ipv4Addr,
    /// The MTU of the TUN device.
    pub mtu: u16,
    /// The IPv6 address of the TUN device.
    pub address_v6: Ipv6Addr,
    /// The prefix length of the client IPv6 network.
    pub prefix_v6: u8,
    /// The client IPv6 network -- the NAT66 rule is written for it.
    pub network_v6: Ipv6Addr,
}

impl Default for IpPlaneConfig {
    fn default() -> Self {
        Self {
            interface: TUN_NAME.to_owned(),
            address: TUN_ADDRESS,
            prefix: TUN_PREFIX,
            network: CLIENT_NETWORK,
            mtu: TUN_MTU,
            address_v6: TUN_ADDRESS_V6,
            prefix_v6: TUN_PREFIX_V6,
            network_v6: CLIENT_NETWORK_V6,
        }
    }
}

// -----------------------------------------------------------------------------
// The errors
// -----------------------------------------------------------------------------

/// What can go wrong while the IP plane is set up or while it runs.
#[derive(Debug, thiserror::Error)]
pub enum IpPlaneError {
    /// The plane needs a Linux TUN device, and this is not Linux.
    #[error("the ip plane needs a Linux tun device: {0}")]
    UnsupportedPlatform(String),
    /// The device could not be opened.
    #[error("the tun device could not be opened: {0}")]
    Open(String),
    /// A command of the system failed.
    #[error("the command failed: {0}")]
    Command(String),
    /// The packet is not an IP packet.
    #[error("the packet is not an IP packet")]
    NotIp,
    /// The packet is too short to be an IP packet.
    #[error("the packet is too short to be an IP packet: {0} bytes")]
    TooShort(usize),
    /// The packet is too large to be carried.
    #[error("the packet is too large to be carried: {0} bytes")]
    TooLarge(usize),
    /// The system call failed.
    #[error("the system call failed: {0}")]
    Io(#[from] std::io::Error),
}

// -----------------------------------------------------------------------------
// The IPv4 header
// -----------------------------------------------------------------------------

/// The header of an IP packet, as far as the box cares.
///
/// The box routes by address and hands the packet to the kernel untouched:
/// only the two addresses and the protocol are ever read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpHeader {
    /// The protocol of the packet: 1 is ICMP, 6 is TCP, 17 is UDP. For IPv6
    /// it is the next header of the packet.
    pub protocol: u8,
    /// Where the packet comes from.
    pub source: IpAddr,
    /// Where the packet goes.
    pub destination: IpAddr,
    /// The length of the header itself, in bytes.
    pub header_len: usize,
}

/// Parse the header of an IP packet.
///
/// IPv4 and IPv6 are both read: the box carries what the client sends, and
/// the client may send either. Anything else is refused.
pub fn parse_ip(packet: &[u8]) -> Result<IpHeader, IpPlaneError> {
    if packet.len() < 1 {
        return Err(IpPlaneError::TooShort(packet.len()));
    }
    match packet[0] >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => Err(IpPlaneError::NotIp),
    }
}

/// Parse the IPv4 header of a packet.
fn parse_ipv4(packet: &[u8]) -> Result<IpHeader, IpPlaneError> {
    if packet.len() < MIN_IPV4_HEADER {
        return Err(IpPlaneError::TooShort(packet.len()));
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < MIN_IPV4_HEADER {
        return Err(IpPlaneError::NotIp);
    }
    if packet.len() < header_len {
        return Err(IpPlaneError::TooShort(packet.len()));
    }
    Ok(IpHeader {
        protocol: packet[9],
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        header_len,
    })
}

/// Parse the IPv6 header of a packet.
///
/// The IPv6 header is a fixed forty bytes: the addresses sit at fixed
/// offsets and the next header is one byte.
fn parse_ipv6(packet: &[u8]) -> Result<IpHeader, IpPlaneError> {
    if packet.len() < MIN_IPV6_HEADER {
        return Err(IpPlaneError::TooShort(packet.len()));
    }
    let mut source = [0u8; 16];
    let mut destination = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    destination.copy_from_slice(&packet[24..40]);
    Ok(IpHeader {
        protocol: packet[6],
        source: IpAddr::V6(Ipv6Addr::from(source)),
        destination: IpAddr::V6(Ipv6Addr::from(destination)),
        header_len: MIN_IPV6_HEADER,
    })
}

// -----------------------------------------------------------------------------
// The peer map
// -----------------------------------------------------------------------------

/// Which peer owns which address.
///
/// The map is shared: the per-peer tasks teach it, and the task that reads
/// the TUN routes by it.
#[derive(Clone, Default)]
pub struct PeerMap {
    peers: Arc<Mutex<HashMap<IpAddr, Arc<dyn PacketPlane>>>>,
}

impl PeerMap {
    /// A new, empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Teach the map that this plane owns this address.
    ///
    /// Both families are keys: a peer owns an IPv4 address and an IPv6
    /// address, and the reply comes back in whichever family it went out.
    pub fn register(&self, address: IpAddr, plane: Arc<dyn PacketPlane>) {
        let mut peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        peers.insert(address, plane);
    }

    /// The plane that owns this address.
    pub fn lookup(&self, address: IpAddr) -> Option<Arc<dyn PacketPlane>> {
        let peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        peers.get(&address).cloned()
    }

    /// Forget the peer that owned this address.
    pub fn remove(&self, address: IpAddr) {
        let mut peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        peers.remove(&address);
    }

    /// How many peers the map knows.
    pub fn len(&self) -> usize {
        let peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        peers.len()
    }

    /// Whether the map knows nobody.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// -----------------------------------------------------------------------------
// The address pool
// -----------------------------------------------------------------------------

/// The addresses the box hands out to the peers behind it.
///
/// Every peer needs its OWN address in the client network: the box routes
/// the replies by address, and two peers on one address would take each
/// other's traffic. The pool is shared by the per-peer tasks, so it is
/// locked.
#[derive(Clone, Default)]
pub struct AddressPool {
    used: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl AddressPool {
    /// A new, empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// The lowest free address of the pool, marked used.
    ///
    /// `None` when the pool is exhausted: every address of the client
    /// network is taken, and the box cannot serve another peer.
    pub fn assign(&self) -> Option<Ipv4Addr> {
        let mut used = self.used.lock().unwrap_or_else(|err| err.into_inner());
        let mut candidate = u32::from(CLIENT_POOL_FIRST);
        let last = u32::from(CLIENT_POOL_LAST);
        while candidate <= last {
            let addr = Ipv4Addr::from(candidate);
            if !used.contains(&addr) {
                used.insert(addr);
                return Some(addr);
            }
            candidate += 1;
        }
        None
    }

    /// Give an address back to the pool: the peer that owned it is gone.
    pub fn release(&self, addr: Ipv4Addr) {
        let mut used = self.used.lock().unwrap_or_else(|err| err.into_inner());
        used.remove(&addr);
    }

    /// How many addresses of the pool are taken.
    pub fn len(&self) -> usize {
        self.used.lock().unwrap_or_else(|err| err.into_inner()).len()
    }

    /// Whether the pool still has a free address.
    pub fn has_free(&self) -> bool {
        let size = u32::from(CLIENT_POOL_LAST) - u32::from(CLIENT_POOL_FIRST) + 1;
        self.len() < size as usize
    }
}

// -----------------------------------------------------------------------------
// The counters
// -----------------------------------------------------------------------------

/// What the plane has counted.
#[derive(Debug, Default)]
pub struct IpPlaneCounters {
    from_tun: AtomicU64,
    to_tun: AtomicU64,
    dropped_unknown: AtomicU64,
    dropped_too_large: AtomicU64,
    dropped_not_ip: AtomicU64,
    write_errors: AtomicU64,
    /// The packets that came from an address the peer was not assigned.
    peer_address_mismatch: AtomicU64,
}

/// The counters as plain numbers -- what the operator's log shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpPlaneStats {
    /// The packets that came out of the TUN.
    pub from_tun: u64,
    /// The packets that went into the TUN.
    pub to_tun: u64,
    /// The packets dropped because nobody owns their destination.
    pub dropped_unknown: u64,
    /// The packets dropped because they were too large.
    pub dropped_too_large: u64,
    /// The packets dropped because they were not IPv4.
    pub dropped_not_ip: u64,
    /// The writes that failed.
    pub write_errors: u64,
    /// The packets dropped because their source address is not the one the
    /// box assigned to that peer.
    pub peer_address_mismatch: u64,
}

impl IpPlaneCounters {
    /// The counters as plain numbers.
    pub fn stats(&self) -> IpPlaneStats {
        IpPlaneStats {
            from_tun: self.from_tun.load(Ordering::Relaxed),
            to_tun: self.to_tun.load(Ordering::Relaxed),
            dropped_unknown: self.dropped_unknown.load(Ordering::Relaxed),
            dropped_too_large: self.dropped_too_large.load(Ordering::Relaxed),
            dropped_not_ip: self.dropped_not_ip.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            peer_address_mismatch: self.peer_address_mismatch.load(Ordering::Relaxed),
        }
    }
}

// -----------------------------------------------------------------------------
// The router
// -----------------------------------------------------------------------------

/// The routing half of the plane: the peer map and the counters.
///
/// It holds no channel of its own, so the task that reads the TUN may hold
/// it without keeping the TUN alive.
#[derive(Clone, Default)]
pub struct Router {
    peers: PeerMap,
    counters: Arc<IpPlaneCounters>,
}

impl Router {
    /// A new, empty router with counters of its own.
    pub fn new() -> Self {
        Self::with_counters(Arc::new(IpPlaneCounters::default()))
    }

    /// A router that counts into these counters.
    pub fn with_counters(counters: Arc<IpPlaneCounters>) -> Self {
        Self {
            peers: PeerMap::new(),
            counters,
        }
    }

    /// The peer map.
    pub fn peers(&self) -> &PeerMap {
        &self.peers
    }

    /// The counters.
    pub fn counters(&self) -> &Arc<IpPlaneCounters> {
        &self.counters
    }

    /// A packet that arrived FROM a peer.
    ///
    /// It teaches the box the peer's address, and it goes into the TUN.
    /// Returns the address the peer was seen at.
    ///
    /// `assigned` is the address the box handed to this peer when it joined.
    /// The assigned address is authoritative: a packet from another address
    /// is not the peer the box knows, and it is dropped and counted.
    ///
    /// `None` means the box assigned nothing -- an older client, which
    /// cannot take an address from the box. Such a peer teaches the box its
    /// address with its first packet, the way the box always did it.
    pub async fn from_peer(
        &self,
        plane: &Arc<dyn PacketPlane>,
        assigned: Option<Ipv4Addr>,
        packet: &[u8],
        to_tun: &mpsc::Sender<Vec<u8>>,
    ) -> Option<IpAddr> {
        if packet.len() > MAX_PACKET_SIZE {
            self.counters.dropped_too_large.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let header = match parse_ip(packet) {
            Ok(header) => header,
            Err(err) => {
                self.counters.dropped_not_ip.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%err, "the packet is not an IP packet -- dropped");
                return None;
            }
        };

        // The ASSIGNED address is authoritative: a peer that sends from
        // another address would take the traffic of the peer that owns it.
        // The peer owns its IPv4 address and the IPv6 address derived from
        // it -- both are the peer's own.
        //
        // A peer that was assigned nothing teaches the box its address with
        // its own first packet.
        if let Some(assigned) = assigned {
            let assigned_v4 = IpAddr::V4(assigned);
            let assigned_v6 = IpAddr::V6(derive_client_v6(assigned));
            if header.source != assigned_v4 && header.source != assigned_v6 {
                self.counters.peer_address_mismatch.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    source = %header.source,
                    assigned = %assigned,
                    "the packet does not come from the assigned address -- dropped"
                );
                return None;
            }
        }

        // The packet teaches the box whose it is.
        self.peers.register(header.source, Arc::clone(plane));

        if to_tun.send(packet.to_vec()).await.is_err() {
            self.counters.write_errors.fetch_add(1, Ordering::Relaxed);
            return Some(header.source);
        }
        self.counters.to_tun.fetch_add(1, Ordering::Relaxed);
        Some(header.source)
    }

    /// A packet that came OUT of the TUN.
    ///
    /// It goes to the peer that owns its destination. A destination nobody
    /// owns is dropped and counted.
    pub async fn from_tun(&self, packet: &[u8]) {
        self.counters.from_tun.fetch_add(1, Ordering::Relaxed);
        if packet.len() > MAX_PACKET_SIZE {
            self.counters.dropped_too_large.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let header = match parse_ip(packet) {
            Ok(header) => header,
            Err(err) => {
                self.counters.dropped_not_ip.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%err, "the tun packet is not an IP packet -- dropped");
                return;
            }
        };
        let Some(peer) = self.peers.lookup(header.destination) else {
            self.counters.dropped_unknown.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                destination = %header.destination,
                "no peer owns the destination -- dropped"
            );
            return;
        };
        if peer.send_packet(packet).await.is_err() {
            self.counters.write_errors.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                destination = %header.destination,
                "the packet did not reach the peer"
            );
        }
    }
}

// -----------------------------------------------------------------------------
// The plane
// -----------------------------------------------------------------------------

/// The box's L3 exit: the TUN device and the peers behind it.
///
/// The device is opened once, at the start of the server, and every peer
/// shares it.
pub struct IpPlane {
    router: Arc<Router>,
    to_tun: mpsc::Sender<Vec<u8>>,
    /// The addresses the box hands out to the peers behind it.
    pool: AddressPool,
    _device: device::Device,
}

impl IpPlane {
    /// Open the box's IP plane: the TUN device, the address, the NAT rules
    /// and the forwarding.
    #[cfg(target_os = "linux")]
    pub fn open(config: IpPlaneConfig) -> Result<Arc<Self>, IpPlaneError> {
        let counters = Arc::new(IpPlaneCounters::default());
        let (mut device, to_tun) = device::Device::open(&config, Arc::clone(&counters))?;
        let from_tun = device.take_from_tun();
        let router = Arc::new(Router::with_counters(Arc::clone(&counters)));

        let plane = Arc::new(Self {
            router: Arc::clone(&router),
            to_tun,
            pool: AddressPool::new(),
            _device: device,
        });

        // The task that reads the TUN and routes every packet it gives.
        if let Some(mut from_tun) = from_tun {
            tokio::spawn(async move {
                while let Some(packet) = from_tun.recv().await {
                    router.from_tun(&packet).await;
                }
                tracing::info!("the tun reader task is done");
            });
        }

        // The counters, every ten seconds, on one line.
        tokio::spawn(log_counters(counters));

        Ok(plane)
    }

    /// Open the box's IP plane.
    ///
    /// The TUN device is a Linux thing: everywhere else the plane refuses,
    /// and the box keeps serving the peers it can.
    #[cfg(not(target_os = "linux"))]
    pub fn open(_config: IpPlaneConfig) -> Result<Arc<Self>, IpPlaneError> {
        Err(IpPlaneError::UnsupportedPlatform(
            "the ip plane needs a Linux tun device".to_owned(),
        ))
    }

    /// The router: the peer map and the counters.
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// The peer map.
    pub fn peers(&self) -> &PeerMap {
        self.router.peers()
    }

    /// The counters.
    pub fn counters(&self) -> &Arc<IpPlaneCounters> {
        self.router.counters()
    }

    /// Teach the box that this plane owns this address.
    ///
    /// The peer owns the IPv4 address AND the IPv6 address derived from it:
    /// both are registered, so a reply in either family finds its way home.
    pub fn register_peer(&self, address: Ipv4Addr, plane: Arc<dyn PacketPlane>) {
        self.peers().register(IpAddr::V4(address), Arc::clone(&plane));
        self.peers()
            .register(IpAddr::V6(derive_client_v6(address)), plane);
    }

    /// The address the box assigns to a peer that joins.
    ///
    /// The lowest free address of the client pool, marked used. `None` when
    /// the pool is exhausted: every address of the client network is taken.
    pub fn assign(&self) -> Option<Ipv4Addr> {
        self.pool.assign()
    }

    /// Give an address back: the peer that owned it is gone.
    ///
    /// The peer leaves the map first, and the address goes back to the pool
    /// after it: while the address is taken, no other peer can own it.
    pub fn release(&self, addr: Ipv4Addr) {
        self.peers().remove(IpAddr::V4(addr));
        self.peers().remove(IpAddr::V6(derive_client_v6(addr)));
        self.pool.release(addr);
    }

    /// Serve one peer: its datagrams go into the TUN, and the packets the TUN
    /// gives back find their way to it.
    ///
    /// The way back is the shared reader task: it reads the TUN and looks the
    /// destination up in the peer map, which this task fills.
    ///
    /// `assigned` is the address the box gave this peer: the peer map holds
    /// it from the moment the peer joined, so the first reply finds its way
    /// home even before the peer sends a packet of its own. `None` for an
    /// older client: it was assigned nothing and teaches the box its address
    /// with its first packet.
    pub async fn serve_peer(
        self: Arc<Self>,
        plane: Arc<dyn PacketPlane>,
        assigned: Option<Ipv4Addr>,
    ) {
        let mut buffer = vec![0u8; DATAGRAM_BUFFER];
        // The address the peer was seen at, when the box assigned none.
        let mut learned: Option<IpAddr> = None;
        loop {
            let count = match plane.recv_packet(&mut buffer).await {
                Ok(count) => count,
                Err(err) => {
                    tracing::debug!(%err, "the peer's plane is closed");
                    break;
                }
            };
            if count == 0 {
                break;
            }
            if let Some(source) = self
                .router
                .from_peer(&plane, assigned, &buffer[..count], &self.to_tun)
                .await
            {
                learned = Some(source);
            }
        }
        // The peer is gone: it leaves the map. The address goes back to the
        // pool when its owner releases it.
        if let Some(source) = learned {
            self.peers().remove(source);
        }
        if let Some(assigned) = assigned {
            self.peers().remove(IpAddr::V4(assigned));
            self.peers().remove(IpAddr::V6(derive_client_v6(assigned)));
        }
    }
}

/// What the plane wire needs from the box's L3 exit.
///
/// The plane session takes the address book as a trait, not as the concrete
/// [`IpPlane`]: the real one needs a TUN device, and the handshake -- the
/// hello, the welcome and the address -- has to be testable without one.
#[async_trait::async_trait]
pub trait AddressBook: Send + Sync {
    /// Hand out an address for a client that asked for one.
    fn assign(&self) -> Option<Ipv4Addr>;

    /// Give the address back: the peer that owned it is gone.
    fn release(&self, addr: Ipv4Addr);

    /// Record that this address belongs to this peer.
    fn register_peer(&self, address: Ipv4Addr, plane: Arc<dyn PacketPlane>);

    /// Serve one peer: its packets go into the TUN, and the packets the TUN
    /// gives back find their way to it.
    async fn serve_peer(self: Arc<Self>, plane: Arc<dyn PacketPlane>, assigned: Option<Ipv4Addr>);
}

#[async_trait::async_trait]
impl AddressBook for IpPlane {
    fn assign(&self) -> Option<Ipv4Addr> {
        IpPlane::assign(self)
    }

    fn release(&self, addr: Ipv4Addr) {
        IpPlane::release(self, addr)
    }

    fn register_peer(&self, address: Ipv4Addr, plane: Arc<dyn PacketPlane>) {
        IpPlane::register_peer(self, address, plane)
    }

    async fn serve_peer(self: Arc<Self>, plane: Arc<dyn PacketPlane>, assigned: Option<Ipv4Addr>) {
        IpPlane::serve_peer(self, plane, assigned).await
    }
}

/// Log the counters, every ten seconds, on one line.
#[cfg(target_os = "linux")]
async fn log_counters(counters: Arc<IpPlaneCounters>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
    // The first tick comes at once: the line is for the operator, and the
    // plane has just come up.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let stats = counters.stats();
        tracing::info!(
            from_tun = stats.from_tun,
            to_tun = stats.to_tun,
            dropped_unknown = stats.dropped_unknown,
            dropped_too_large = stats.dropped_too_large,
            dropped_not_ip = stats.dropped_not_ip,
            write_errors = stats.write_errors,
            peer_address_mismatch = stats.peer_address_mismatch,
            "the ip plane counters"
        );
    }
}

// -----------------------------------------------------------------------------
// The tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::error::MirageError;

    /// A plane that remembers what it was given.
    #[derive(Default)]
    struct RecordingPlane {
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingPlane {
        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap_or_else(|err| err.into_inner()).clone()
        }
    }

    #[async_trait::async_trait]
    impl PacketPlane for RecordingPlane {
        async fn send_packet(&self, packet: &[u8]) -> Result<(), MirageError> {
            self.sent
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .push(packet.to_vec());
            Ok(())
        }

        async fn recv_packet(&self, _buf: &mut [u8]) -> Result<usize, MirageError> {
            Err(MirageError::Protocol(
                "the recording plane has nothing to read".into(),
            ))
        }

        fn max_packet_size(&self) -> usize {
            MAX_PACKET_SIZE
        }
    }

    /// A small IPv4 packet, built by hand.
    fn ipv4(source: [u8; 4], destination: [u8; 4], protocol: u8) -> Vec<u8> {
        let mut packet = vec![0u8; MIN_IPV4_HEADER];
        // Version 4, header length five words.
        packet[0] = 0x45;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    /// A small IPv6 packet, built by hand.
    fn ipv6(source: [u8; 16], destination: [u8; 16], next_header: u8) -> Vec<u8> {
        let mut packet = vec![0u8; MIN_IPV6_HEADER];
        // Version 6.
        packet[0] = 0x60;
        packet[6] = next_header;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet
    }

    /// The address of the peer in the tests.
    fn peer_address() -> Ipv4Addr {
        Ipv4Addr::new(10, 77, 0, 2)
    }

    /// The IPv6 address of the peer in the tests.
    fn peer_address_v6() -> Ipv6Addr {
        derive_client_v6(peer_address())
    }

    #[test]
    fn the_header_of_a_packet_is_read() {
        let packet = ipv4([10, 77, 0, 2], [1, 1, 1, 1], 17);
        let header = parse_ipv4(&packet).expect("an IPv4 header");
        assert_eq!(header.source, IpAddr::V4(peer_address()));
        assert_eq!(header.destination, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(header.protocol, 17);
        assert_eq!(header.header_len, MIN_IPV4_HEADER);
    }

    #[test]
    fn the_header_of_an_ipv6_packet_is_read() {
        let mut source = [0u8; 16];
        source[0] = 0xfd;
        source[1] = 0x77;
        source[15] = 2;
        let mut destination = [0u8; 16];
        destination[0] = 0x20;
        destination[1] = 0x01;
        destination[15] = 1;

        let packet = ipv6(source, destination, 17);
        let header = parse_ipv6(&packet).expect("an IPv6 header");
        assert_eq!(header.source, IpAddr::V6(peer_address_v6()));
        assert_eq!(
            header.destination,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(header.protocol, 17);
        assert_eq!(header.header_len, MIN_IPV6_HEADER);
    }

    #[test]
    fn the_version_of_the_packet_picks_the_family() {
        // Version 4 is read as IPv4.
        let packet = ipv4([10, 77, 0, 2], [1, 1, 1, 1], 6);
        assert!(parse_ip(&packet).is_ok());

        // Version 6 is read as IPv6.
        let mut packet = ipv6([0u8; 16], [0u8; 16], 6);
        packet[15] = 2;
        assert!(parse_ip(&packet).is_ok());
    }

    #[test]
    fn a_packet_that_is_not_ip_is_refused() {
        // Version 5: not an IP packet at all.
        let mut packet = ipv4([10, 77, 0, 2], [1, 1, 1, 1], 6);
        packet[0] = 0x50;
        assert!(matches!(parse_ip(&packet), Err(IpPlaneError::NotIp)));

        // Too short to be a header at all.
        assert!(matches!(
            parse_ip(&[0x45, 0, 0, 0]),
            Err(IpPlaneError::TooShort(4))
        ));
    }

    #[test]
    fn an_ipv6_packet_that_is_too_short_is_refused() {
        assert!(matches!(
            parse_ipv6(&[0u8; 8]),
            Err(IpPlaneError::TooShort(8))
        ));
    }

    #[test]
    fn the_peer_map_remembers_who_owns_an_address() {
        let map = PeerMap::new();
        assert!(map.is_empty());
        assert!(map.lookup(IpAddr::V4(peer_address())).is_none());

        let peer: Arc<dyn PacketPlane> = Arc::new(RecordingPlane::default());
        map.register(IpAddr::V4(peer_address()), peer);
        assert!(map.lookup(IpAddr::V4(peer_address())).is_some());
        assert_eq!(map.len(), 1);

        map.remove(IpAddr::V4(peer_address()));
        assert!(map.lookup(IpAddr::V4(peer_address())).is_none());
        assert!(map.is_empty());
    }

    #[test]
    fn the_peer_map_keeps_both_families_of_a_peer() {
        let map = PeerMap::new();
        let peer: Arc<dyn PacketPlane> = Arc::new(RecordingPlane::default());
        map.register(IpAddr::V4(peer_address()), peer.clone());
        map.register(IpAddr::V6(peer_address_v6()), peer);

        assert!(map.lookup(IpAddr::V4(peer_address())).is_some());
        assert!(map.lookup(IpAddr::V6(peer_address_v6())).is_some());
        assert_eq!(map.len(), 2);
    }

    #[tokio::test]
    async fn a_packet_from_a_peer_teaches_the_box_whose_it_is() {
        let (to_tun, mut from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        let plane: Arc<dyn PacketPlane> = peer.clone();
        let packet = ipv4([10, 77, 0, 2], [1, 1, 1, 1], 6);

        let source = router.from_peer(&plane, Some(peer_address()), &packet, &to_tun).await;
        assert_eq!(source, Some(IpAddr::V4(peer_address())));

        // The packet is on its way into the tun.
        let written = from_tun.recv().await.expect("a packet");
        assert_eq!(written, packet);

        // The peer owns its address now.
        assert!(router.peers().lookup(IpAddr::V4(peer_address())).is_some());
        assert_eq!(router.counters().stats().to_tun, 1);
    }

    #[tokio::test]
    async fn a_packet_from_a_peer_in_ipv6_is_accepted() {
        let (to_tun, mut from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        let plane: Arc<dyn PacketPlane> = peer.clone();

        let mut source = [0u8; 16];
        source[0] = 0xfd;
        source[1] = 0x77;
        source[15] = 2;
        let packet = ipv6(source, [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 6);

        let seen = router
            .from_peer(&plane, Some(peer_address()), &packet, &to_tun)
            .await;
        assert_eq!(seen, Some(IpAddr::V6(peer_address_v6())));

        let written = from_tun.recv().await.expect("a packet");
        assert_eq!(written, packet);
        assert!(router.peers().lookup(IpAddr::V6(peer_address_v6())).is_some());
        assert_eq!(router.counters().stats().to_tun, 1);
    }

    #[tokio::test]
    async fn an_ipv6_reply_finds_its_peer() {
        let (_to_tun, _from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        router
            .peers()
            .register(IpAddr::V6(peer_address_v6()), peer.clone());

        let mut destination = [0u8; 16];
        destination[0] = 0xfd;
        destination[1] = 0x77;
        destination[15] = 2;
        let reply = ipv6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], destination, 6);
        router.from_tun(&reply).await;

        assert_eq!(peer.sent(), vec![reply]);
        assert_eq!(router.counters().stats().from_tun, 1);
        assert_eq!(router.counters().stats().dropped_unknown, 0);
    }

    #[tokio::test]
    async fn a_packet_from_the_tun_goes_to_the_peer_that_owns_the_destination() {
        let (_to_tun, _from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        router
            .peers()
            .register(IpAddr::V4(peer_address()), peer.clone());

        // The reply comes back from the internet towards the peer.
        let reply = ipv4([1, 1, 1, 1], [10, 77, 0, 2], 6);
        router.from_tun(&reply).await;

        assert_eq!(peer.sent(), vec![reply]);
        assert_eq!(router.counters().stats().from_tun, 1);
        assert_eq!(router.counters().stats().dropped_unknown, 0);
    }

    #[tokio::test]
    async fn a_packet_for_an_unknown_destination_is_dropped_and_counted() {
        let (_to_tun, _from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();

        let packet = ipv4([1, 1, 1, 1], [10, 77, 0, 9], 6);
        router.from_tun(&packet).await;

        assert_eq!(router.counters().stats().dropped_unknown, 1);
    }

    #[tokio::test]
    async fn a_packet_that_is_not_ipv4_is_dropped_and_counted() {
        let (to_tun, mut from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        let plane: Arc<dyn PacketPlane> = peer.clone();

        let mut packet = ipv4([10, 77, 0, 2], [1, 1, 1, 1], 6);
        packet[0] = 0x60;
        let source = router.from_peer(&plane, Some(peer_address()), &packet, &to_tun).await;

        assert_eq!(source, None);
        assert_eq!(router.counters().stats().dropped_not_ip, 1);
        // Nothing went into the tun.
        assert!(from_tun.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_packet_that_is_too_large_is_dropped_and_counted() {
        let (to_tun, mut from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        let plane: Arc<dyn PacketPlane> = peer.clone();

        let mut packet = ipv4([10, 77, 0, 2], [1, 1, 1, 1], 6);
        packet.resize(MAX_PACKET_SIZE + 1, 0);
        let source = router.from_peer(&plane, Some(peer_address()), &packet, &to_tun).await;

        assert_eq!(source, None);
        assert_eq!(router.counters().stats().dropped_too_large, 1);
        assert!(from_tun.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_peer_without_an_assignment_teaches_the_box_its_address() {
        let (to_tun, mut from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        let plane: Arc<dyn PacketPlane> = peer.clone();

        // The peer was assigned nothing -- an older client -- and sends from
        // the address it always had.
        let own = Ipv4Addr::new(10, 77, 0, 1);
        let packet = ipv4([10, 77, 0, 1], [1, 1, 1, 1], 6);
        let source = router.from_peer(&plane, None, &packet, &to_tun).await;
        assert_eq!(source, Some(IpAddr::V4(own)));

        let written = from_tun.recv().await.expect("a packet");
        assert_eq!(written, packet);
        // The box knows the peer by the address it speaks from.
        assert!(router.peers().lookup(IpAddr::V4(own)).is_some());
        assert_eq!(router.counters().stats().peer_address_mismatch, 0);
    }

    #[tokio::test]
    async fn a_packet_from_another_address_is_dropped_and_counted() {
        let (to_tun, mut from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        let plane: Arc<dyn PacketPlane> = peer.clone();

        // The peer was assigned one address and sends from another one.
        let packet = ipv4([10, 77, 0, 9], [1, 1, 1, 1], 6);
        let source = router.from_peer(&plane, Some(peer_address()), &packet, &to_tun).await;

        assert_eq!(source, None);
        assert_eq!(router.counters().stats().peer_address_mismatch, 1);
        // Nothing went into the tun.
        assert!(from_tun.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_peer_that_joined_owns_its_address_before_its_first_packet() {
        let (_to_tun, _from_tun) = mpsc::channel::<Vec<u8>>(8);
        let router = Router::new();
        let peer = Arc::new(RecordingPlane::default());
        let plane: Arc<dyn PacketPlane> = peer.clone();
        let assigned = Ipv4Addr::new(10, 77, 0, 7);

        // The peer joins: the box puts its address into the map right away.
        router.peers().register(IpAddr::V4(assigned), plane);

        // The first reply comes back before the peer sent a packet of its own.
        let reply = ipv4([1, 1, 1, 1], [10, 77, 0, 7], 6);
        router.from_tun(&reply).await;

        assert_eq!(peer.sent(), vec![reply]);
        assert_eq!(router.counters().stats().from_tun, 1);
        assert_eq!(router.counters().stats().dropped_unknown, 0);
    }

    #[test]
    fn the_pool_hands_out_the_lowest_free_address() {
        let pool = AddressPool::new();
        assert_eq!(pool.assign(), Some(Ipv4Addr::new(10, 77, 0, 2)));
        assert_eq!(pool.assign(), Some(Ipv4Addr::new(10, 77, 0, 3)));
        assert_eq!(pool.assign(), Some(Ipv4Addr::new(10, 77, 0, 4)));
    }

    #[test]
    fn a_released_address_is_handed_out_again() {
        let pool = AddressPool::new();
        let first = pool.assign().expect("an address");
        let second = pool.assign().expect("an address");
        pool.release(first);
        assert_eq!(pool.assign(), Some(first));
        assert_eq!(pool.assign(), Some(Ipv4Addr::new(10, 77, 0, 4)));
        assert_ne!(first, second);
    }

    #[test]
    fn the_pool_runs_out() {
        let pool = AddressPool::new();
        let count = u32::from(CLIENT_POOL_LAST) - u32::from(CLIENT_POOL_FIRST) + 1;
        for _ in 0..count {
            assert!(pool.assign().is_some());
        }
        // Every address of the client network is taken.
        assert_eq!(pool.assign(), None);
        assert_eq!(pool.len(), count as usize);
    }
}
