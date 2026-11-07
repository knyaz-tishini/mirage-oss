# mirage-oss

Libraries and the box program for Mirage. Identifiers, the wire, the mux,
the data plane, and the process that answers a public port.

This repository does not contain the fleet (mesh, quorum, secd, warden),
the store client, or the operator. Those stay in their own repositories
and depend on this one.

## Crates

| Crate | What it is | crates.io |
|---|---|---|
| `mirage-ids` | Typed identifiers. No I/O. | with the workspace |
| `mirage-core` | Shared node types: wire plane, mesh plane, listeners. | with the workspace |
| `mirage-protocol` | Handshake, session, carriers, camouflage, transports. | with the workspace |
| `mirage-mux` | Stream mux: frames, windows, sessions. | with the workspace |
| `mirage-control-plane` | Client dial primitives. Folder is `mirage-dial-core`. | with the workspace |
| `mirage-wire-http-client` | HTTP over the wire for a process that is not the operator. | with the workspace |
| `mirage-shared-types` | Types shared by workers. | with the workspace |
| `mirage-node` | Data plane as a library. No fleet dependency. | with the workspace |
| `mirage-subscriber-gate` | Authenticate a customer dial and dispatch the tunnel. | with the workspace |
| `mirage-vpn` | A session between a client and a terminator. | with the workspace |
| `mirage-vpn-mesh` | That session inside an onion chain. | with the workspace |
| `mirage-vpn-cli` | The server and client programs around the session. | with the workspace |
| `mirage-chain-leg` | Put a session into a chain and bring it out at the exit. | with the workspace |
| `mirage-blindtoken` | RFC 9474 blind RSA token. | not published |
| `mirage-ringmember` | Merkle ring-membership credential. | not published |
| `mirage-hostsec` | Host hardening, nftables, posture. | not published |
| `mirage-perimeter` | The box's public front door. | not published |

The workspace `publish` flag is off. The four crates in the last group
also set `publish = false` on themselves.

License: MIT.
