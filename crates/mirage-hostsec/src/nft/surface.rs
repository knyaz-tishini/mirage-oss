//! The box's admitted-port table, rendered once for both of its writers.
//!
//! # Why this lives here and not in the operator
//!
//! `inet mirage_surface` is written by two processes that never run on the
//! same machine: `operator-box`'s `POST /surface/apply`, which pushes the
//! signed face list into the perimeter's capsule, and `mirage-secd`, which
//! renders the boot lockdown below and then keeps re-rendering it,
//! continuously, from that same perimeter's LIVE face list (`mirage-secd::
//! perimeter_admission` + `fw::ensure_boot_lockdown`'s reconcile loop). Two
//! independent renderers of the kernel table would be two answers to "what
//! does our filter look like", and this tree already paid for that mistake
//! once — see `mirage-secd::fw`'s module doc, where a second port policy
//! with its own default drifted until the day it would have dropped every
//! face its own box published. So the kernel table has exactly one writer
//! now — secd, deriving from the perimeter it can ask locally — and the
//! operator's role moved a layer up: it decides what the perimeter should
//! serve, not what the kernel should admit.
//!
//! One function, two callers, one port list per call. The list is the only
//! thing that differs, and neither caller can change the shape of the rules
//! without changing it for the other.
//!
//! # The two lines before the table, and why they are load-bearing
//!
//! `nft -f` on a table that already exists APPENDS to its chains. It does not
//! replace them. Applying twice therefore stacks two rule sets in one chain,
//! and since every rule is an `accept`, the OLD port list keeps admitting
//! traffic forever. Measured 2026-08-05 after the persona roll:
//! `ru-hostkey-203.0.113.10` carried three stacked copies and was still accepting
//! `3000` and `8080` — ports the settle phase had just removed from its faces
//! — while every instrument reported the box settled and default-deny.
//!
//! So the script declares the table (a no-op when it is already there, and the
//! reason the `delete` cannot fail on a fresh box), deletes it with everything
//! in it, and creates it again. All three are in ONE `nft -f` file, which
//! nftables applies as a single transaction: there is no instant at which the
//! box has no filter.

/// The one table name. Both writers use this; nothing else may create it.
pub const SURFACE_TABLE: &str = "mirage_surface";

/// The recovery door — the ONLY port admitted before the perimeter is
/// confirmed up, and nothing more.
///
/// This is NOT a face list and it is not meant to track one. `mirage-secd`
/// owns the box's admitted port set now, continuously, by asking the
/// perimeter what it actually serves (`mirage-secd::perimeter_admission`,
/// `fw::ensure_boot_lockdown` + the reconcile loop it starts): while the
/// perimeter cannot be proven to be up, the kernel admits `:22` alone and
/// hands it to mshd's recovery door; the moment the perimeter answers with a
/// face list, the kernel admits EXACTLY that list, whatever it is. This
/// constant is only ever the FIRST half of that — the fixed fact "until
/// something else takes over, the operator gets in and nothing else does".
///
/// # Was `&[22, 80, 443]` from 2026-08-18 to 2026-08-18, and both directions were wrong
///
/// The reasoning at the time was that this should mirror
/// `mirage-perimeter::config::PerimeterConfig::baseline()` — the same three
/// ports the perimeter binds as its own pre-capsule surface — on the theory
/// that the listener and the filter are "one statement made in two places"
/// and must move together. That conflates two different questions: WHAT the
/// perimeter intends to bind (`baseline()`'s job) is not the same fact as
/// WHETHER the perimeter is actually up and serving it (this constant's
/// job). A static three-port mirror gets the first boot right and then
/// never moves again — it does not shrink when the perimeter loses a face,
/// and it does not grow when a live capsule adds one, because nothing here
/// ever re-asks. That is a list in the source standing in for a fact that
/// only the perimeter itself can state, which is exactly the shape the
/// reconcile loop above this doc exists to replace.
///
/// Read literally, it is `&[22]` because that is what it always was before
/// this const carried any doctrine about the perimeter's face list at all —
/// the recovery door is `mshd`'s alone, independent of any capsule, and it
/// answers on one port.
///
/// # The incident this still has to prevent
///
/// Measured on `nl-example-203.0.113.31`, 2026-08-18: `mirage-perimeter` was
/// serving 80, 443 and 8443 while `inet mirage_surface` admitted
/// `tcp dport { 22 }` alone — the table EXISTED, so the boot-lockdown check
/// of the day left it alone on sight rather than reading what it actually
/// admitted. That was never a case for widening this constant; it was the
/// handover never happening — nothing on the box was asking the perimeter
/// what it served and rewriting the filter to match. `fw::
/// ensure_boot_lockdown` now reads the table back instead of trusting its
/// presence, and the reconcile loop this module doc points at is what
/// actually closes the gap: once the perimeter is up, this constant stops
/// mattering and the live face list does.
pub const BOOT_LOCKDOWN_PORTS: &[u16] = &[22];

/// Render the ruleset for one box's admitted ports, per protocol.
///
/// Pure and testable: the port lists in, the nft script out.
///
/// # Why UDP is a parameter and not a branch
///
/// This function rendered TCP only, while `mirage-secd/src/fw.rs`'s read side
/// (`parse_admitted_udp_ports`) has always parsed `udp dport` generically. So
/// a box could REPORT a UDP admission it had no way to WRITE. That asymmetry
/// is where the UDP face plan starts
/// (`docs/mirage/plans/mirage-udp-face-2026-08-31.md`): the face does not
/// exist because nothing can admit it, and nothing can admit it because this
/// generator took one list.
///
/// An empty `udp_ports` renders byte-for-byte what this function rendered
/// before, so the signature lands ahead of any UDP face and changes nothing
/// until one exists.
///
/// The `forward` chain rides inside the same transaction as `input`, for the
/// same reason: there is no instant, and no second table, in which the box's
/// forward policy could be something other than what this function renders.
#[must_use]
pub fn surface_ruleset(tcp_ports: &[u16], udp_ports: &[u16]) -> String {
    let ports = tcp_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    // Its own line only when there is something to admit. An empty
    // `udp dport { }` is not a harmless no-op: nft rejects the empty set and
    // the whole transaction fails, taking the TCP surface down with it.
    let udp_rule = if udp_ports.is_empty() {
        String::new()
    } else {
        let list = udp_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!("\x20   udp dport {{ {list} }} accept\n")
    };
    let table = SURFACE_TABLE;
    format!(
        "table inet {table} {{}}\n\
         delete table inet {table}\n\
         table inet {table} {{\n\
         \x20 chain input {{\n\
         \x20   type filter hook input priority filter; policy drop;\n\
         \n\
         \x20   # Anything we started. Without this the box cannot receive the\n\
         \x20   # answer to its own dial, and every outbound path dies.\n\
         \x20   ct state established,related accept\n\
         \x20   ct state invalid drop\n\
         \x20   iif lo accept\n\
         \n\
         \x20   # Path-MTU discovery and the error types that carry network\n\
         \x20   # semantics. Echo-request is NOT here: that is the discovery\n\
         \x20   # signal this whole table exists to remove.\n\
         \x20   icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept\n\
         \x20   icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} accept\n\
         \n\
         \x20   # IPv6 neighbour discovery is not optional: drop it and the box\n\
         \x20   # cannot resolve its own gateway.\n\
         \x20   icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept\n\
         \n\
         \x20   # DHCP renewal. Broadcast, so conntrack does not cover it, and a\n\
         \x20   # box that loses its lease loses its address.\n\
         \x20   udp sport 67 udp dport 68 accept\n\
         \x20   ip6 nexthdr udp udp sport 547 udp dport 546 accept\n\
         \n\
         \x20   # The admitted surface. Exactly the perimeter's live face\n\
         \x20   # list once secd can read one; the recovery door alone\n\
         \x20   # until then.\n\
         \x20   tcp dport {{ {ports} }} accept\n\
         {udp_rule}\
         \x20 }}\n\
         \n\
         \x20 # Nothing on this fleet forwards: net.ipv4.ip_forward measured 0\n\
         \x20 # on all nine boxes 2026-08-08, so this chain is free today. It\n\
         \x20 # exists so a hoster image update or an operator flipping\n\
         \x20 # ip_forward back on lands on a box that already refuses to\n\
         \x20 # route, rather than one with no forwarding policy at all. inet\n\
         \x20 # covers both v4 and v6 in the one hook, same as input above.\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority filter; policy drop;\n\
         \x20 }}\n\
         }}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim the whole two-parameter change rests on: an empty UDP list
    /// renders exactly what this function rendered before it had one.
    ///
    /// Asserted against the DHCP exceptions rather than against "no `udp`
    /// anywhere" — the ruleset has always carried `udp sport 67 udp dport 68`
    /// and its v6 twin, so a test that forbade the substring would be
    /// asserting something false about the old output too.
    #[test]
    fn an_empty_udp_list_adds_no_accept_set() {
        let r = surface_ruleset(&[22, 80, 443], &[]);
        assert_eq!(
            r.matches("udp dport {").count(),
            0,
            "an empty set must render NOTHING: nft rejects `udp dport {{ }}`              and would fail the whole transaction, TCP surface included"
        );
        // The two protocol exceptions are still there and still unconditional.
        assert!(r.contains("udp sport 67 udp dport 68 accept"));
        assert!(r.contains("udp sport 547 udp dport 546 accept"));
    }

    /// One rule, inside the input chain, and the append-guard ordering
    /// unaffected by its presence.
    #[test]
    fn a_udp_list_renders_exactly_one_accept_set_inside_the_chain() {
        let r = surface_ruleset(&[22], &[443, 8443]);
        assert_eq!(r.matches("udp dport {").count(), 1, "{r}");
        assert!(r.contains("udp dport { 443, 8443 } accept"), "{r}");

        let create = r.find("table inet mirage_surface {
").expect("create");
        let udp = r.find("udp dport {").expect("udp rule");
        let chain_end = r.find("  }
").unwrap_or(r.len());
        assert!(
            create < udp,
            "the rule must be inside the created table, not before it"
        );
        assert!(udp < chain_end, "the rule must be inside `chain input`");

        // The guard this module exists for is untouched by the new line.
        let declare = r.find("table inet mirage_surface {}").expect("declare");
        let delete = r.find("delete table inet mirage_surface").expect("delete");
        assert!(declare < delete && delete < create);
    }

    #[test]
    fn declare_delete_create_precede_the_table_body() {
        let r = surface_ruleset(&[22, 80, 443], &[]);
        let declare = r.find("table inet mirage_surface {}").expect("declare");
        let delete = r.find("delete table inet mirage_surface").expect("delete");
        let create = r.find("table inet mirage_surface {\n").expect("create");
        assert!(
            declare < delete && delete < create,
            "the append-guard is the ORDER of these three, not their presence"
        );
    }

    #[test]
    fn exactly_one_port_rule_is_rendered() {
        // Two would mean the old list still admits alongside the new one —
        // the stacked-rules failure this shape exists to prevent.
        assert_eq!(surface_ruleset(&[22, 80], &[]).matches("tcp dport").count(), 1);
    }

    #[test]
    fn boot_lockdown_admits_the_recovery_door_and_nothing_else() {
        assert_eq!(BOOT_LOCKDOWN_PORTS, &[22]);
        let r = surface_ruleset(BOOT_LOCKDOWN_PORTS, &[]);
        assert!(r.contains("tcp dport { 22 } accept"));
    }

    #[test]
    fn conntrack_accept_precedes_the_port_list() {
        // Reversed, the box cannot receive the answer to its own dial and
        // every outbound path dies while the filter still reads correct.
        let r = surface_ruleset(&[22, 80], &[]);
        let est = r.find("ct state established,related accept").expect("ct");
        assert!(est < r.find("tcp dport").expect("dport"));
    }

    #[test]
    fn echo_request_is_never_admitted() {
        let r = surface_ruleset(&[22], &[]);
        assert!(!r.contains("echo-request"));
    }
}
