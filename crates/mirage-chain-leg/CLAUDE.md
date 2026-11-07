# mirage-chain-leg

The leg of a chain: the part that puts a customer's session into a chain and
brings it out at the exit.

## Why this crate exists

Two boxes that both put a customer's bytes into a chain were doing the same
four things in two places, and those four things are the ones that must not
drift apart:

* building the chain's configuration — the stream plane and the datagram
  plane, which are two chains;
* minting the `RoleSigned` credential, bound to the exit's node id;
* building the protocol chain the leg is spoken over — V9, with the
  credential in it;
* dialling the chain and carrying the customer's bytes.

This crate is those four things. The consumers keep their own way of
describing a chain and hand this crate a [`LegSpec`].

| consumer | what it keeps | what it takes from here |
|---|---|---|
| `mirage-standalone` | how a standalone box reads its chain (TOML, env) and the operator key it signs with | the whole leg |
| `mirage2node`'s `mirage-edge-fleet` | how the fleet's edge holds many chains and rounds between them | the credential mint, the configuration, the protocol |

## The two planes

The chain's two planes are two chains, not one chain with two ways to speak:

* the **stream** plane carries the customer's TCP;
* the **datagram** plane carries the customer's UDP over a native UDP tunnel,
  with its own handshake and its own frames — a datagram stays a datagram all
  the way down and never rides a stream.

A chain whose hops have no datagram door carries TCP only, and says so out
loud rather than sending the datagram out of the wrong box.

## The rules

- **The entry hop's camouflage is never set here.** It is the hop's own
  published face, and the dialer resolves it from the peer table at dial time.
  That is also what makes a one-hop chain take the onion path instead of a
  plain handshake.
- **The credential is bound to the exit's node id.** A leg that is replayed at
  a different box does not verify there.
- **The datagram chain has its own id.** Sharing the stream chain's id would
  put the two planes on one address in the node's registry.
- **The wire version is V9.** V8 has no credential slot, and a leg without a
  credential is a leg the hop refuses.
- **The destination is framed `[2B len BE][target_utf8]`** — the framing the
  exit's own reader expects.
- **A `Debug` of the leg never prints the slice or the excerpt.** Both carry
  key material.

## Tests

```bash
cargo test -p mirage-chain-leg -j 1
```

The tests cover the configuration (the entry hop's camouflage, the datagram
chain's own id and protocol, a chain that carries TCP only), the credential
(a minted token that verifies under the operator key it was bound to) and the
framing of the destination.
