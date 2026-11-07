# mirage-vpn

The **VPN variant** of Mirage: the part that turns a session into something an
application can use.

## Where this sits

```
  ┌─ variants ──────────────────────────────────────────────────────────┐
  │  VPN   — a session between a client and a terminator, no onion      │
  │  mesh  — the same session inside an onion chain of N hops           │
  └────────────────────────────────────────────────────────────────────┘
  ┌─ modes ────────────────────────────────────────────────────────────┐
  │  client — "I call the terminator"                                  │
  │  server — "I am the terminator"                                    │
  └────────────────────────────────────────────────────────────────────┘
  ┌─ cores ────────────────────────────────────────────────────────────┐
  │  handshake · session · carriers · onion                            │
  └────────────────────────────────────────────────────────────────────┘
```

- The **cores** live in `mirage-protocol` (`mirage_protocol::cores`).
- The **modes** live there too (`mirage_protocol::modes`).
- The **VPN variant** is this crate. The **mesh variant** is `mirage-vpn-mesh`.

## What lives here

- `carrier.rs` — the carriers of the VPN: MWG and КВИК (over Mirage's own
  camouflage axes) and the SOCKS5 tube. Plus the traits `Carrier` and
  `CarrierListener`, and the bridge `tunnel_to_stream`.
- `channel.rs` — the message channel over a session: a two-byte length
  prefix over the byte stream the session core gives. The flow plane's
  control messages ride on it.
- `flow.rs` — the flow plane: many flows over one session.
- `socks5.rs` — the SOCKS5 surface of the client, and the exit of the server.
- `peer.rs` — the peer table. A peer's static public key is its name.
- `connector.rs` — the connector: a session in a tube and a `connect()` inside
  it. This is the shape the hatchery knows from WireGuard.
- `testing.rs` — the memory tunnel the tests run on.

**There is no crypto stack here.** The handshake is Mirage's own V9 handshake
(`mirage_protocol::cores::handshake`), and the session is Mirage's own
`MirageCoreTunnel`. This crate adds the data plane and nothing else.

**There is no packet plane here.** No IP packets, no `AllowedIPs`, no address
pool, no route table, no system TUN.

## Why there is no TUN, and why that is not a gap

The client does not need a system TUN: the application talks SOCKS5 to a
local listener, and the listener carries the flow to the exit. The exit opens
the connection and the bytes come back.

A TUN belongs to the **underlay** — it is what the underlay does with the
traffic it is given. The VPN runs *inside* the underlay's tube (a SOCKS5
tunnel or the underlay's own TUN), and it carries flows, not packets.

That is why the packet plane was removed: it contradicted the scheme. A
packet plane needs an L3 interface on both ends, and the far end of a VPN is
not an interface — it is a program that opens connections.

## The name is not resolved on the near side

A CONNECT with a domain name is carried **unresolved** to the exit. The near
side never learns what the far side is connecting to, and the DNS query does
not leak the fact that a tunnel is in use.

## The four carriers

MWG, КВИК, the SOCKS5 tube and the onion chain are **four carriers of one
protocol**. What differs is the pipe under the session — nothing else.

| carrier | pipe | where |
|---|---|---|
| MWG (МиражВГ) | UDP with a junk burst and a magic marker | here |
| КВИК (МиражКВИК) | a QUIC connection with our ALPN | here |
| SOCKS5 | a CONNECT tunnel through a proxy | here |
| onion | the chain itself | `mirage-vpn-mesh` |

The onion carrier is the only one that belongs to the mesh: in the VPN a
multi-hop route is a **pump** (the node carries the bytes and does not take
any layer off), while in the mesh every hop **peels exactly one layer**.

## The connector

The connector is what the hatchery needs: raise a session in a tube and hand
out a `connect()` that gives a stream to a target. `FlowStream` is an
`AsyncRead` and an `AsyncWrite`, so it drops into everything that speaks
those — the same way a WireGuard peer's stream does.

```rust
let carrier = Arc::new(CamouflageCarrier::new(config, server));
let connector = Connector::new(carrier, server_pub, client_priv, mesh_id);
let mut stream = connector.connect(Target::Named("example.com".into(), 443)).await?;
```

## Rules

- A peer that is not in the table is refused. Do not "temporarily" accept one.
- Never print a private key.
- The exit resolves the name. The near side never does.
- Never wait for one peer before looking at the door: every connection is
  finished in a task of its own.

## Tests

```bash
cargo test -p mirage-vpn -j 1
```

The tests cover the flow plane over a memory tunnel, the SOCKS5 surface (the
name reaches the exit unresolved), and the refusal of a UDP association.
