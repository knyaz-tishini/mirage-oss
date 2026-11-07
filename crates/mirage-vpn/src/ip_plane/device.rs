//! The TUN device of the box.
//!
//! The device is opened once, at the start of the server, and every peer
//! shares it. Two OS threads serve it -- one reads the packets the kernel
//! produced, the other writes the packets the peers sent -- and the packets
//! travel between the threads and the async side over tokio channels.
//!
//! The device is a Linux thing: on every other platform the module holds a
//! stub, and the plane refuses with a clear error.

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::CString;
    use std::os::fd::RawFd;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use super::super::{IpPlaneConfig, IpPlaneCounters, IpPlaneError};
    use crate::metrics::DEVICE_COUNTERS;

    /// The character device that hands out TUN devices.
    const TUN_DEVICE: &str = "/dev/net/tun";

    /// The flags the device is opened with: a plain IP tunnel, with no
    /// packet-information header in front of the packets.
    const TUN_FLAGS: libc::c_short = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

    /// The buffer the reader thread reads into: an IP packet is at most
    /// 65535 bytes.
    const READ_BUFFER: usize = 65535;

    /// How long the reader thread waits for the device before it looks at the
    /// stop flag again.
    const POLL_TIMEOUT_MS: i32 = 500;

    /// How many drops pass between two log lines.
    ///
    /// A drop is counted every time; it is only logged once in a while, or
    /// the log would drown in the very thing it is meant to report.
    const LOG_EVERY: u64 = 100;

    /// Where the forwarding switch of the kernel lives.
    const IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

    /// Where the forwarding switch of the kernel lives, for IPv6.
    ///
    /// IPv6 has its own switch, and a kernel built without IPv6 does not
    /// have the file at all: the box then serves IPv4 only.
    const IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

    /// The `ifreq` the TUNSETIFF ioctl takes.
    ///
    /// The kernel reads a `struct ifreq`: a 16-byte name and a union whose
    /// first member is a short of flags. The union is 24 bytes wide here, so
    /// the struct is never smaller than the kernel's own.
    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _rest: [u8; 22],
    }

    /// The box's TUN device, and the two threads that serve it.
    ///
    /// The sender of the writer channel belongs to the plane: the writer
    /// thread stops when it is gone, so the device never closes the file
    /// descriptor under the writer's feet.
    pub struct Device {
        fd: RawFd,
        stop: Arc<AtomicBool>,
        reader: Option<std::thread::JoinHandle<()>>,
        writer: Option<std::thread::JoinHandle<()>>,
        from_tun: Option<mpsc::Receiver<Vec<u8>>>,
        _state: SystemState,
    }

    impl Device {
        /// Open the device, set it up, and start the two threads.
        ///
        /// Returns the device and the channel the packets go into.
        pub fn open(
            config: &IpPlaneConfig,
            counters: Arc<IpPlaneCounters>,
        ) -> Result<(Self, mpsc::Sender<Vec<u8>>), IpPlaneError> {
            let fd = open_tun(config)?;
            let mut state = SystemState::default();
            if let Err(err) = configure(config, &mut state) {
                // Everything that was changed is put back.
                drop(state);
                unsafe { libc::close(fd) };
                return Err(err);
            }

            let stop = Arc::new(AtomicBool::new(false));
            let (from_tx, from_rx) = mpsc::channel::<Vec<u8>>(256);
            let (to_tx, to_rx) = mpsc::channel::<Vec<u8>>(256);

            let reader = spawn_reader(fd, Arc::clone(&stop), from_tx)?;
            let writer = spawn_writer(fd, to_rx, Arc::clone(&counters))?;

            Ok((
                Self {
                    fd,
                    stop,
                    reader: Some(reader),
                    writer: Some(writer),
                    from_tun: Some(from_rx),
                    _state: state,
                },
                to_tx,
            ))
        }

        /// Take the channel of the packets the device produced.
        pub fn take_from_tun(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
            self.from_tun.take()
        }
    }

    impl Drop for Device {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            // The writer stops when the last sender is gone -- the plane
            // holds it and drops it before the device.
            if let Some(handle) = self.writer.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.reader.take() {
                let _ = handle.join();
            }
            unsafe { libc::close(self.fd) };
            tracing::info!("the tun device is closed");
        }
    }

    /// Open the device and name it.
    fn open_tun(config: &IpPlaneConfig) -> Result<RawFd, IpPlaneError> {
        let path =
            CString::new(TUN_DEVICE).map_err(|_| IpPlaneError::Open(format!("{TUN_DEVICE}?")))?;
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(IpPlaneError::Open(format!("{TUN_DEVICE}: {err}")));
        }
        if let Err(err) = set_interface(fd, &config.interface) {
            unsafe { libc::close(fd) };
            return Err(err);
        }
        Ok(fd)
    }

    /// Tell the kernel what kind of device this is.
    fn set_interface(fd: RawFd, interface: &str) -> Result<(), IpPlaneError> {
        let name = interface.as_bytes();
        if name.len() >= libc::IFNAMSIZ {
            return Err(IpPlaneError::Open(format!(
                "the interface name {interface} is too long"
            )));
        }
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: TUN_FLAGS,
            _rest: [0; 22],
        };
        for (slot, byte) in request.name.iter_mut().zip(name) {
            *slot = *byte as libc::c_char;
        }
        let result = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &mut request as *mut IfReq) };
        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(IpPlaneError::Open(format!("TUNSETIFF {interface}: {err}")));
        }
        tracing::info!(interface = %interface, "the tun device is open");
        Ok(())
    }

    /// Set the device up: its address, its MTU, the forwarding and the rules.
    fn configure(config: &IpPlaneConfig, state: &mut SystemState) -> Result<(), IpPlaneError> {
        configure_interface(config)?;
        let forwarding = enable_forwarding(state)?;
        let rules = install_rules(config, state)?;

        // One line for the operator: the box is really an L3 exit.
        tracing::info!(
            interface = %config.interface,
            address = %format!("{}/{}", config.address, config.prefix),
            address_v6 = %format!("{}/{}", config.address_v6, config.prefix_v6),
            mtu = config.mtu,
            forwarding,
            nat_rules = rules,
            "the ip plane is up"
        );
        Ok(())
    }

    /// Give the device its address and its MTU, and bring it up.
    fn configure_interface(config: &IpPlaneConfig) -> Result<(), IpPlaneError> {
        let interface = config.interface.as_str();
        let address = format!("{}/{}", config.address, config.prefix);
        run(
            "ip",
            &[
                "addr".to_owned(),
                "add".to_owned(),
                address,
                "dev".to_owned(),
                interface.to_owned(),
            ],
        )?;
        run(
            "ip",
            &[
                "link".to_owned(),
                "set".to_owned(),
                interface.to_owned(),
                "mtu".to_owned(),
                config.mtu.to_string(),
            ],
        )?;
        run(
            "ip",
            &[
                "link".to_owned(),
                "set".to_owned(),
                interface.to_owned(),
                "up".to_owned(),
            ],
        )?;

        // The IPv6 address of the client network. A kernel without IPv6
        // refuses it: the box then serves IPv4 only, and says so.
        if let Err(err) = configure_interface_v6(config) {
            tracing::warn!(%err, "the ipv6 address could not be set -- ipv6 stays off");
        }
        Ok(())
    }

    /// Give the device its IPv6 address.
    ///
    /// The address is added with `nodad`: the device is a tunnel with no
    /// neighbour to answer the duplicate address check, so the kernel would
    /// only waste time on it.
    fn configure_interface_v6(config: &IpPlaneConfig) -> Result<(), IpPlaneError> {
        let address = format!("{}/{}", config.address_v6, config.prefix_v6);
        run(
            "ip",
            &[
                "-6".to_owned(),
                "addr".to_owned(),
                "add".to_owned(),
                address,
                "dev".to_owned(),
                config.interface.clone(),
                "nodad".to_owned(),
            ],
        )
    }

    /// Turn the forwarding on, and remember the old value.
    fn enable_forwarding(state: &mut SystemState) -> Result<bool, IpPlaneError> {
        let old = std::fs::read_to_string(IPV4_FORWARD)
            .map_err(|err| IpPlaneError::Command(format!("{IPV4_FORWARD}: {err}")))?;
        let old = old.trim().to_owned();
        std::fs::write(IPV4_FORWARD, "1")
            .map_err(|err| IpPlaneError::Command(format!("{IPV4_FORWARD}: {err}")))?;
        tracing::info!(old = %old, new = "1", "the ip forwarding is on");
        state.forwarding = Some(old);

        // IPv6 forwarding is a switch of its own.
        state.forwarding_v6 = enable_forwarding_v6();
        Ok(true)
    }

    /// Turn the IPv6 forwarding on, and remember the old value.
    ///
    /// `None` when the kernel has no such switch, or refuses to write it:
    /// the box then serves IPv4 only, and the operator sees why.
    fn enable_forwarding_v6() -> Option<String> {
        let Ok(old) = std::fs::read_to_string(IPV6_FORWARD) else {
            tracing::warn!(
                path = IPV6_FORWARD,
                "the kernel has no ipv6 forwarding switch -- ipv6 stays off"
            );
            return None;
        };
        let old = old.trim().to_owned();
        if let Err(err) = std::fs::write(IPV6_FORWARD, "1") {
            tracing::warn!(%err, "the ipv6 forwarding could not be turned on");
            return None;
        }
        tracing::info!(old = %old, new = "1", "the ipv6 forwarding is on");
        Some(old)
    }

    /// Put the NAT and the forwarding rules in place.
    ///
    /// Every rule is checked before it is added, so the box may be started
    /// twice without doubling the rules. Only the rules the box added are
    /// removed when it goes: the table is never flushed.
    fn install_rules(config: &IpPlaneConfig, state: &mut SystemState) -> Result<bool, IpPlaneError> {
        for rule in rules(config) {
            if rule.exists() {
                tracing::info!(rule = %rule.label(), "the rule is already there");
                continue;
            }
            match rule.add() {
                Ok(()) => state.rules.push(rule),
                // The IPv6 rules are a bonus: a box whose kernel has no
                // IPv6 NAT still serves its clients over IPv4.
                Err(err) if rule.binary == "ip6tables" => {
                    tracing::warn!(
                        rule = %rule.label(),
                        %err,
                        "the ipv6 rule could not be added -- ipv6 stays off"
                    );
                }
                Err(err) => return Err(err),
            }
        }
        Ok(true)
    }

    /// The rules the box needs: the masquerade and the two forwarding rules.
    ///
    /// Both families are covered: the IPv4 rules are `iptables` rules, the
    /// IPv6 ones are `ip6tables` rules -- NAT66 masquerades the client
    /// network the same way NAT masquerades the IPv4 one.
    fn rules(config: &IpPlaneConfig) -> Vec<Rule> {
        vec![
            Rule {
                binary: "iptables",
                table: Some("nat"),
                spec: vec![
                    "POSTROUTING".to_owned(),
                    "-s".to_owned(),
                    format!("{}/{}", config.network, config.prefix),
                    "-j".to_owned(),
                    "MASQUERADE".to_owned(),
                ],
                at_top: false,
            },
            Rule {
                binary: "iptables",
                table: None,
                spec: vec![
                    "FORWARD".to_owned(),
                    "-i".to_owned(),
                    config.interface.clone(),
                    "-j".to_owned(),
                    "ACCEPT".to_owned(),
                ],
                at_top: true,
            },
            Rule {
                binary: "iptables",
                table: None,
                spec: vec![
                    "FORWARD".to_owned(),
                    "-o".to_owned(),
                    config.interface.clone(),
                    "-j".to_owned(),
                    "ACCEPT".to_owned(),
                ],
                at_top: true,
            },
            Rule {
                binary: "ip6tables",
                table: Some("nat"),
                spec: vec![
                    "POSTROUTING".to_owned(),
                    "-s".to_owned(),
                    format!("{}/{}", config.network_v6, config.prefix_v6),
                    "-j".to_owned(),
                    "MASQUERADE".to_owned(),
                ],
                at_top: false,
            },
            Rule {
                binary: "ip6tables",
                table: None,
                spec: vec![
                    "FORWARD".to_owned(),
                    "-i".to_owned(),
                    config.interface.clone(),
                    "-j".to_owned(),
                    "ACCEPT".to_owned(),
                ],
                at_top: true,
            },
            Rule {
                binary: "ip6tables",
                table: None,
                spec: vec![
                    "FORWARD".to_owned(),
                    "-o".to_owned(),
                    config.interface.clone(),
                    "-j".to_owned(),
                    "ACCEPT".to_owned(),
                ],
                at_top: true,
            },
        ]
    }

    /// Run a command of the system, and log it.
    fn run(program: &str, args: &[String]) -> Result<(), IpPlaneError> {
        let label = format!("{program} {}", args.join(" "));
        tracing::info!(command = %label, "the ip plane runs a command");
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|err| IpPlaneError::Command(format!("{label}: {err}")))?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!(
                command = %label,
                status = %output.status,
                stdout = %stdout.trim(),
                stderr = %stderr.trim(),
                "the command failed"
            );
            return Err(IpPlaneError::Command(format!(
                "{label}: {} {}",
                stderr.trim(),
                stdout.trim()
            )));
        }
        tracing::info!(command = %label, "the command succeeded");
        Ok(())
    }

    /// What the box changed in the system, and what it puts back when it
    /// goes.
    #[derive(Default)]
    struct SystemState {
        /// The old value of the forwarding switch, when the box changed it.
        forwarding: Option<String>,
        /// The old value of the IPv6 forwarding switch, when the box changed
        /// it. `None` when the box could not change it.
        forwarding_v6: Option<String>,
        /// The rules the box added -- and only those.
        rules: Vec<Rule>,
    }

    impl Drop for SystemState {
        fn drop(&mut self) {
            if let Some(old) = self.forwarding.take() {
                match std::fs::write(IPV4_FORWARD, format!("{old}\n")) {
                    Ok(()) => {
                        tracing::info!(value = %old.trim(), "the ip forwarding is restored")
                    }
                    Err(err) => {
                        tracing::error!(%err, "the ip forwarding could not be restored")
                    }
                }
            }
            if let Some(old) = self.forwarding_v6.take() {
                match std::fs::write(IPV6_FORWARD, format!("{old}\n")) {
                    Ok(()) => {
                        tracing::info!(value = %old.trim(), "the ipv6 forwarding is restored")
                    }
                    Err(err) => {
                        tracing::error!(%err, "the ipv6 forwarding could not be restored")
                    }
                }
            }
            for rule in self.rules.drain(..) {
                match rule.remove() {
                    Ok(()) => tracing::info!(rule = %rule.label(), "the rule is removed"),
                    Err(err) => tracing::error!(
                        %err,
                        rule = %rule.label(),
                        "the rule could not be removed"
                    ),
                }
            }
        }
    }

    /// One iptables rule the box added.
    struct Rule {
        /// The program the rule lives in: `iptables` or `ip6tables`.
        binary: &'static str,
        /// The table the rule lives in. `None` is the filter table.
        table: Option<&'static str>,
        /// The rule itself, without the table and without the flag.
        spec: Vec<String>,
        /// Put the rule at the TOP of the chain instead of at its end.
        ///
        /// The filter rules must stand in front of the chains the host
        /// already has: a box with Docker has a FORWARD policy of DROP and
        /// Docker's own chains in front of ours, and a rule at the end of
        /// the chain never gets to say yes.
        at_top: bool,
    }

    impl Rule {
        /// The rule as the operator reads it.
        fn label(&self) -> String {
            match self.table {
                Some(table) => format!("{} -t {table} {}", self.binary, self.spec.join(" ")),
                None => format!("{} {}", self.binary, self.spec.join(" ")),
            }
        }

        /// The arguments of a call for this rule.
        fn args(&self, flag: &str) -> Vec<String> {
            let mut args = Vec::new();
            if let Some(table) = self.table {
                args.push("-t".to_owned());
                args.push(table.to_owned());
            }
            args.push(flag.to_owned());
            if self.at_top {
                // The chain is the first word of the spec, and the position
                // goes right after it.
                args.push(self.spec[0].clone());
                args.push("1".to_owned());
                args.extend(self.spec[1..].iter().cloned());
            } else {
                args.extend(self.spec.iter().cloned());
            }
            args
        }

        /// Whether the rule is already in the chain.
        fn exists(&self) -> bool {
            Command::new(self.binary)
                .args(self.args("-C"))
                .output()
                .map_or(false, |out| out.status.success())
        }

        /// Put the rule in the chain.
        fn add(&self) -> Result<(), IpPlaneError> {
            let flag = if self.at_top { "-I" } else { "-A" };
            run(self.binary, &self.args(flag))
        }

        /// Take the rule out of the chain.
        fn remove(&self) -> Result<(), IpPlaneError> {
            run(self.binary, &self.args("-D"))
        }
    }

    /// The reader thread: it reads the device and hands the packets over.
    fn spawn_reader(
        fd: RawFd,
        stop: Arc<AtomicBool>,
        sender: mpsc::Sender<Vec<u8>>,
    ) -> Result<std::thread::JoinHandle<()>, IpPlaneError> {
        std::thread::Builder::new()
            .name("mgt0-reader".into())
            .spawn(move || {
                let mut buffer = vec![0u8; READ_BUFFER];
                while !stop.load(Ordering::Relaxed) {
                    match wait_readable(fd, POLL_TIMEOUT_MS) {
                        Ok(false) => continue,
                        Ok(true) => {}
                        Err(err) => {
                            tracing::debug!(%err, "the tun poll failed");
                            break;
                        }
                    }
                    let count =
                        unsafe { libc::read(fd, buffer.as_mut_ptr().cast::<libc::c_void>(), buffer.len()) };
                    if count < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        tracing::debug!(%err, "the tun read failed");
                        break;
                    }
                    let count = count as usize;
                    if count == 0 {
                        continue;
                    }
                    // The channel to the plane is bounded. When it is full the
                    // packet cannot ride the plane: it is dropped, and the
                    // drop is counted -- a drop nobody counts is a packet the
                    // operator cannot account for.
                    match sender.try_send(buffer[..count].to_vec()) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            let drops = DEVICE_COUNTERS.note_dropped_channel_full();
                            if drops % LOG_EVERY == 0 {
                                tracing::debug!(
                                    drops,
                                    "the tun reader channel is full -- the packet is dropped"
                                );
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            tracing::debug!("the tun reader channel is closed");
                            break;
                        }
                    }
                }
                tracing::info!("the tun reader thread is done");
            })
            .map_err(|err| IpPlaneError::Open(format!("the reader thread: {err}")))
    }

    /// The writer thread: it takes the packets and writes them into the
    /// device.
    fn spawn_writer(
        fd: RawFd,
        mut receiver: mpsc::Receiver<Vec<u8>>,
        counters: Arc<IpPlaneCounters>,
    ) -> Result<std::thread::JoinHandle<()>, IpPlaneError> {
        std::thread::Builder::new()
            .name("mgt0-writer".into())
            .spawn(move || {
                loop {
                    // The channel from the plane is bounded. When it is full
                    // the plane is waiting for room: the writer is behind.
                    if receiver.len() >= receiver.max_capacity() {
                        let full = DEVICE_COUNTERS.note_write_channel_full();
                        if full % LOG_EVERY == 0 {
                            tracing::debug!(
                                full,
                                "the tun writer channel is full -- the plane waits for room"
                            );
                        }
                    }
                    let Some(packet) = receiver.blocking_recv() else {
                        break;
                    };
                    let count = unsafe {
                        libc::write(fd, packet.as_ptr().cast::<libc::c_void>(), packet.len())
                    };
                    if count < 0 {
                        let err = std::io::Error::last_os_error();
                        counters.write_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(%err, "the tun write failed");
                    }
                }
                tracing::info!("the tun writer thread is done");
            })
            .map_err(|err| IpPlaneError::Open(format!("the writer thread: {err}")))
    }

    /// Wait until the device has something to say.
    fn wait_readable(fd: RawFd, timeout_ms: i32) -> Result<bool, IpPlaneError> {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(IpPlaneError::Io(err));
        }
        Ok(ready > 0)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    /// The device of a platform that has none.
    ///
    /// The TUN device is a Linux thing: on every other platform the plane
    /// refuses with a clear error, and the rest of the VPN keeps working.
    #[allow(dead_code)]
    pub struct Device;
}

pub use imp::Device;
