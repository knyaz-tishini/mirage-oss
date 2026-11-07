# mirage-vpn-cli

The Mirage VPN as a program: a server and a client.

The protocol lives in `mirage-vpn`. This crate is the operator's side of it:
the config files, the listeners, and the two commands.

## The commands

```bash
mirage-vpn keygen --out server.key     # the private key goes to the file, the public key to the screen
mirage-vpn serve  --config server.json  # the server
mirage-vpn connect --config client.json # the client
```

`keygen` never prints the private key: a key that is shown on the screen ends
up in a screenshot. It goes into the file, and only the path is printed.

## The shape of the traffic

```text
  the application
        │  SOCKS5 CONNECT example.com:443
   ┌────▼────────┐
   │ Socks5      │   the local listener (the client)
   │ listener    │
   └────┬────────┘
        │  Flow::open(target)
   ┌────▼────────┐
   │  FlowPlane  │   the session, the keys, the rekey
   └────┬────────┘
        │  MWG / MKVIK / a tunnel through a SOCKS5 proxy
   ┌────▼────────┐
   │   server    │   the exit
   └─────────────┘
```

There is no system TUN and no route to set up. The SOCKS5 listener is the
whole surface the application needs, and the name in a CONNECT is carried
UNRESOLVED to the exit — the near side never learns what the far side is
connecting to.

## The config files

They are JSON. The server's:

```json
{
  "private_key": "<base64>",
  "peers": [ { "name": "laptop", "public_key": "<base64>" } ],
  "listeners": {
    "mwg": { "bind": "0.0.0.0:51820" },
    "mkvik": { "bind": "0.0.0.0:51821", "alpn": ["h3"] },
    "tunnel": "0.0.0.0:51822"
  },
  "mesh_id": "mirage-vpn",
  "exit": { "mode": "direct" }
}
```

The three listeners are three ways into the same server. `tunnel` is the one
for a session that arrives **through a SOCKS5 proxy**: the proxy opens a
CONNECT tunnel to that port, and the session runs inside it. The name of the
server is resolved by the proxy.

The MWG port carries its own axis parameters — the magic byte and the junk
burst — and **both ends have to agree on them**. The same is true of the
ALPN of the QUIC endpoint.

`mesh_id` is baked into the handshake on both sides: the two ends have to
carry the same one, or the handshake does not confirm.

The exit is where the flows go. `{ "mode": "direct" }` opens the connections
itself; `{ "mode": "socks5", "proxy": "127.0.0.1:1080" }` hands every flow to
a local SOCKS5 proxy — that is how the server's own system TUN is used, since
the TUN service exposes its chains as SOCKS5 listeners.

The client's:

```json
{
  "private_key": "<base64>",
  "server_public_key": "<base64>",
  "transport": { "kind": "mwg", "server": "203.0.113.7:51820" },
  "socks5_listen": "127.0.0.1:1080",
  "mesh_id": "mirage-vpn"
}
```

The transport is `mwg`, `mkvik` or `tunnel`. The `tunnel` one takes a proxy
as well: `{ "kind": "tunnel", "server": "vpn.example.com:51822", "proxy":
"127.0.0.1:1080" }`.

The MWG and КВИК transports take the same axis parameters as the listeners of
the server, and the defaults are the same on both sides.

## The ports that cannot be learned afterwards

The MWG port and the QUIC endpoint are bound **inside the protocol's own
driver**, so the port has to be known before the server starts. The tunnel
port is bound by the listener itself, and the address it landed on comes back
in the handle — so the tunnel may be asked for port 0, and the MWG and КВИК
ones may not.

## Rules

- The private key is written to a file and never printed.
- A peer that is not in the config is refused at the handshake — the server
  does not "temporarily" accept one.
- The exit never resolves a name on behalf of the near side.
- Every connection is finished in a task of its own. A server that waits for
  one peer before it looks at the door leaves the next peer knocking in vain.

## Tests

```bash
cargo test -p mirage-vpn-cli -j 1
```

The tests are end-to-end: a server, a client, a SOCKS5 on the client, and a
byte that goes all the way through — once over MWG, once over КВИК, and once
through a SOCKS5 proxy to the server.
