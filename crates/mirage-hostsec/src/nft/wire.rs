//! Pure byte serializers for netlink/nftables messages.
//!
//! No `cfg(linux)` gate — this module compiles and its tests run on any OS.
//! All nftables NLA_U32 / NLA_U64 values are big-endian on the wire.
//!
//! # Wire layout recap (from spec)
//!
//! ```text
//! [nlmsghdr 16 B][nfgenmsg 4 B][nlattr…]
//!
//! nlmsghdr: nlmsg_len(u32-LE) nlmsg_type(u16-LE) nlmsg_flags(u16-LE)
//!           nlmsg_seq(u32-LE) nlmsg_pid(u32-LE, =0)
//!
//! nfgenmsg: nfgen_family(u8) version(u8=0) res_id(u16-BE)
//!
//! nlattr:   nla_len(u16-LE, hdr+payload unpadded)
//!           nla_type(u16-LE, OR NLA_F_NESTED=0x8000 for nested)
//!           [payload, padded to 4-byte boundary]
//! ```

// ── Netlink constants ────────────────────────────────────────────────────────

/// `NFNL_SUBSYS_NFTABLES << 8` — base for all nftables message types.
///
/// `NFNL_SUBSYS_NFTABLES == 10` (NOT 12 — 12 is `NFNL_SUBSYS_HOOK`, and also
/// the `NETLINK_NETFILTER` socket protocol number; do not conflate them). Using
/// 12 here addresses every NFT op to the HOOK subsystem, which the kernel
/// rejects fleet-wide with EOPNOTSUPP/EINVAL.
pub const NFNL_NFTABLES_BASE: u16 = 10 << 8; // 0x0A00

// Batch envelope message types (absolute, NOT offset by subsys).
pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x0010;
pub const NFNL_MSG_BATCH_END: u16 = 0x0011;

// NFT opcodes (add to NFNL_NFTABLES_BASE).
pub const NFT_MSG_NEWTABLE: u16 = 0;
/// `DELTABLE` — deletes a table and everything nested under it (chains,
/// sets, rules). Used by the egress policy's flush-then-rebuild cycle.
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_NEWRULE: u16 = 6;
/// `DELRULE` — with a table and chain but NO rule handle, deletes every rule
/// in that chain and leaves the chain, its sets and their elements intact.
///
/// That distinction is the whole reason it is used: re-applying the ban
/// policy must reset the RULE ORDER without forgetting a single live ban.
pub const NFT_MSG_DELRULE: u16 = 8;
pub const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
pub const NFT_MSG_DELSETELEM: u16 = 14;

// NLM_F_* flags.
pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_CREATE: u16 = 0x0400;
pub const NLM_F_APPEND: u16 = 0x0800;

/// FLAGS_ADD = REQUEST|ACK|CREATE (idempotent, no EXCL).
pub const FLAGS_ADD: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
/// FLAGS_APPEND = REQUEST|ACK|CREATE|APPEND.
pub const FLAGS_APPEND: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;
/// FLAGS_DEL = REQUEST|ACK.
pub const FLAGS_DEL: u16 = NLM_F_REQUEST | NLM_F_ACK;
/// FLAGS_BATCH = REQUEST.
pub const FLAGS_BATCH: u16 = NLM_F_REQUEST;

/// `NLA_F_NESTED` — OR into `nla_type` for nested attribute containers.
pub const NLA_F_NESTED: u16 = 0x8000;

// nfgenmsg families.
pub const NFPROTO_UNSPEC: u8 = 0;
pub const NFPROTO_INET: u8 = 1;

/// `nfgenmsg.res_id` for batch begin/end = `NFNL_SUBSYS_NFTABLES` = 10
/// (written as BE by `NlMsgBuilder::new`). htons(10) = `[0x00, 0x0A]` on the wire.
pub const BATCH_RES_ID: u16 = 10;

// ── nlmsghdr / nfgenmsg sizes ────────────────────────────────────────────────

const NLMSGHDR_LEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
/// Base message size before any attributes.
pub const MSG_HEADER_LEN: usize = NLMSGHDR_LEN + NFGENMSG_LEN; // 20

// ── NlMsgBuilder ─────────────────────────────────────────────────────────────

/// Builds a single netlink message (`nlmsghdr` + `nfgenmsg` + attributes).
///
/// Call [`NlMsgBuilder::new`], append attributes, then [`NlMsgBuilder::finish`]
/// to get the padded `Vec<u8>`.  `nlmsg_len` is patched in-place when
/// attributes are appended and on `finish`.
pub struct NlMsgBuilder {
    buf: Vec<u8>,
}

impl NlMsgBuilder {
    /// Create a new message.
    ///
    /// `nlmsg_len` starts at 20 (header + nfgenmsg) and grows with each attr.
    /// `res_id` = 0 for inner messages; [`BATCH_RES_ID`] for batch begin/end.
    pub fn new(nlmsg_type: u16, flags: u16, family: u8, res_id: u16) -> Self {
        let mut buf = Vec::with_capacity(128);
        // nlmsghdr
        buf.extend_from_slice(&(MSG_HEADER_LEN as u32).to_le_bytes()); // nlmsg_len (patched later)
        buf.extend_from_slice(&nlmsg_type.to_le_bytes()); // nlmsg_type
        buf.extend_from_slice(&flags.to_le_bytes()); // nlmsg_flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_seq = 0
        buf.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_pid = 0
        // nfgenmsg
        buf.push(family); // nfgen_family
        buf.push(0); // version = NFNETLINK_V0
        buf.extend_from_slice(&res_id.to_be_bytes()); // res_id (BE)
        Self { buf }
    }

    /// Current byte length of the message.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Append a raw attribute (nla_len covers hdr+payload; padded to 4 bytes).
    ///
    /// `nla_type` should already have `NLA_F_NESTED` ORed in if needed.
    pub fn append_attr(&mut self, nla_type: u16, payload: &[u8]) {
        let hdr_payload_len = 4 + payload.len(); // 4 = sizeof(nlattr hdr)
        let padded = align4(hdr_payload_len);

        self.buf.extend_from_slice(&(hdr_payload_len as u16).to_le_bytes()); // nla_len (unpadded)
        self.buf.extend_from_slice(&nla_type.to_le_bytes()); // nla_type
        self.buf.extend_from_slice(payload);
        // Padding bytes.
        let pad = padded - hdr_payload_len;
        for _ in 0..pad {
            self.buf.push(0);
        }

        // Patch nlmsg_len at offset 0.
        let new_len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&new_len.to_le_bytes());
    }

    /// Append a nul-terminated string attribute.
    pub fn append_str(&mut self, nla_type: u16, s: &str) {
        let mut payload = s.as_bytes().to_vec();
        payload.push(0); // nul terminator
        self.append_attr(nla_type, &payload);
    }

    /// Append a big-endian u32 attribute.
    pub fn append_be32(&mut self, nla_type: u16, val: u32) {
        self.append_attr(nla_type, &val.to_be_bytes());
    }

    /// Append a big-endian u64 attribute.
    pub fn append_be64(&mut self, nla_type: u16, val: u64) {
        self.append_attr(nla_type, &val.to_be_bytes());
    }

    /// Append a nested attribute container built with `f`.
    ///
    /// Sets `NLA_F_NESTED` on `nla_type`.  The callback receives `self` so it
    /// can directly append child attrs; the nested attr's own `nla_len` is
    /// computed from the difference in `buf.len()` before/after.
    pub fn append_nested<F>(&mut self, nla_type: u16, f: F)
    where
        F: FnOnce(&mut Self),
    {
        // Write placeholder header (4 bytes).
        let hdr_off = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // nla_len placeholder
        self.buf.extend_from_slice(&(nla_type | NLA_F_NESTED).to_le_bytes());

        let payload_start = self.buf.len();

        // Let caller fill in child attrs.
        f(self);

        let payload_len = self.buf.len() - payload_start;
        let nla_len = (4 + payload_len) as u16; // 4 = nlattr hdr
        self.buf[hdr_off..hdr_off + 2].copy_from_slice(&nla_len.to_le_bytes());

        // Pad to 4-byte boundary.
        let total_written = 4 + payload_len;
        let pad = align4(total_written) - total_written;
        for _ in 0..pad {
            self.buf.push(0);
        }

        // Patch the outer nlmsg_len.
        let new_len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&new_len.to_le_bytes());
    }

    /// Consume the builder and return the finished message bytes.
    ///
    /// The buffer is already 4-aligned by construction; `nlmsg_len` is
    /// already patched.  This is a zero-copy consume.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Round up to the next multiple of 4.
#[inline]
pub fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ── Batch envelope ────────────────────────────────────────────────────────────

/// Wrap `msgs` in a `BATCH_BEGIN` / `BATCH_END` envelope and concatenate into
/// a single buffer ready for one `sendmsg`.
///
/// Inner messages are concatenated as-is (they are already padded to 4 bytes).
pub fn build_batch(msgs: &[Vec<u8>]) -> Vec<u8> {
    let begin = batch_begin();
    let end = batch_end();

    let total: usize = begin.len() + msgs.iter().map(|m| m.len()).sum::<usize>() + end.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&begin);
    for m in msgs {
        out.extend_from_slice(m);
    }
    out.extend_from_slice(&end);
    out
}

fn batch_begin() -> Vec<u8> {
    NlMsgBuilder::new(NFNL_MSG_BATCH_BEGIN, FLAGS_BATCH, NFPROTO_UNSPEC, BATCH_RES_ID).finish()
}

fn batch_end() -> Vec<u8> {
    NlMsgBuilder::new(NFNL_MSG_BATCH_END, FLAGS_BATCH, NFPROTO_UNSPEC, BATCH_RES_ID).finish()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── align4 ───────────────────────────────────────────────────────────────

    #[test]
    fn align4_rounds_up() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }

    // ── nlmsghdr basics ──────────────────────────────────────────────────────

    #[test]
    fn empty_msg_len_is_20() {
        let b = NlMsgBuilder::new(0x0C00, FLAGS_ADD, NFPROTO_INET, 0).finish();
        // nlmsg_len at offset 0, LE.
        let len = u32::from_le_bytes(b[0..4].try_into().unwrap());
        assert_eq!(len, 20, "base msg must be 20 bytes");
        assert_eq!(b.len(), 20);
    }

    #[test]
    fn nlmsg_type_and_flags_written_correctly() {
        let b = NlMsgBuilder::new(0x0C03, FLAGS_APPEND, NFPROTO_INET, 0).finish();
        let nlmsg_type = u16::from_le_bytes(b[4..6].try_into().unwrap());
        let flags = u16::from_le_bytes(b[6..8].try_into().unwrap());
        assert_eq!(nlmsg_type, 0x0C03);
        assert_eq!(flags, FLAGS_APPEND);
    }

    #[test]
    fn nfgenmsg_family_and_version() {
        let b = NlMsgBuilder::new(0x0C00, FLAGS_ADD, NFPROTO_INET, 0).finish();
        assert_eq!(b[16], NFPROTO_INET); // family
        assert_eq!(b[17], 0); // version = NFNETLINK_V0
    }

    // ── attribute layout ─────────────────────────────────────────────────────

    #[test]
    fn append_str_attr_nla_len_and_padding() {
        // "fw\0" = 3 bytes payload; nla_len = 4+3 = 7; padded to 8.
        let mut b = NlMsgBuilder::new(0x0C00, FLAGS_ADD, NFPROTO_INET, 0);
        b.append_str(1 /* NFTA_TABLE_NAME */, "fw");
        let buf = b.finish();

        // attr starts at offset 20.
        let nla_len = u16::from_le_bytes(buf[20..22].try_into().unwrap());
        let nla_type = u16::from_le_bytes(buf[22..24].try_into().unwrap());
        assert_eq!(nla_len, 7, "hdr(4) + 'fw\\0'(3) = 7");
        assert_eq!(nla_type, 1);
        assert_eq!(&buf[24..27], b"fw\0");
        assert_eq!(buf[27], 0, "padding byte");

        // Total message length = 20 + 8 = 28 (4-aligned).
        let msg_len = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(msg_len, 28);
        assert_eq!(buf.len(), 28);
    }

    #[test]
    fn append_be32_is_big_endian() {
        let mut b = NlMsgBuilder::new(0x0C00, FLAGS_ADD, NFPROTO_INET, 0);
        b.append_be32(2 /* NFTA_TABLE_FLAGS */, 0xDEAD_BEEF);
        let buf = b.finish();
        // BE bytes at [24..28].
        assert_eq!(&buf[24..28], &0xDEAD_BEEFu32.to_be_bytes());
    }

    #[test]
    fn append_be64_is_big_endian_timeout() {
        // timeout = 3 600 000 ms = 0x36EE_80
        let timeout_ms: u64 = 3_600_000;
        let mut b = NlMsgBuilder::new(0x0C0C, FLAGS_ADD, NFPROTO_INET, 0);
        b.append_be64(11 /* NFTA_SET_TIMEOUT */, timeout_ms);
        let buf = b.finish();
        let expected = timeout_ms.to_be_bytes();
        assert_eq!(&buf[24..32], &expected);
    }

    // ── nested attrs ─────────────────────────────────────────────────────────

    #[test]
    fn nested_attr_has_nla_f_nested_set() {
        let mut b = NlMsgBuilder::new(0x0C03, FLAGS_ADD, NFPROTO_INET, 0);
        b.append_nested(4 /* NFTA_CHAIN_HOOK */, |inner| {
            inner.append_be32(1 /* NFTA_HOOK_HOOKNUM */, 1);
        });
        let buf = b.finish();
        // Outer nested attr at offset 20.
        let outer_type = u16::from_le_bytes(buf[22..24].try_into().unwrap());
        assert!(
            outer_type & NLA_F_NESTED != 0,
            "NLA_F_NESTED must be set; got {outer_type:#06x}"
        );
    }

    #[test]
    fn nested_attr_nla_len_includes_child() {
        // One nested attr with one be32 child.
        // child: 4(hdr) + 4(be32) = 8 bytes.
        // outer: 4(hdr) + 8(child) = 12 bytes; padded = 12.
        let mut b = NlMsgBuilder::new(0x0C03, FLAGS_ADD, NFPROTO_INET, 0);
        b.append_nested(4, |inner| {
            inner.append_be32(1, 1);
        });
        let buf = b.finish();
        let outer_nla_len = u16::from_le_bytes(buf[20..22].try_into().unwrap());
        assert_eq!(outer_nla_len, 12, "4(hdr)+4(hdr)+4(be32)=12");
        // Total = 20 + 12 = 32.
        let msg_len = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(msg_len, 32);
    }

    // ── batch envelope ───────────────────────────────────────────────────────

    #[test]
    fn batch_envelope_begin_end_types() {
        let batch = build_batch(&[]);
        // First 20 bytes = BATCH_BEGIN.
        let begin_type = u16::from_le_bytes(batch[4..6].try_into().unwrap());
        assert_eq!(begin_type, NFNL_MSG_BATCH_BEGIN);
        // Second message = BATCH_END at offset 20.
        let end_type = u16::from_le_bytes(batch[24..26].try_into().unwrap());
        assert_eq!(end_type, NFNL_MSG_BATCH_END);
    }

    #[test]
    fn batch_begin_res_id_is_htons_nftables_subsys() {
        let batch = build_batch(&[]);
        // nfgenmsg.res_id at offset 18 (bytes 18-19 within first msg).
        // res_id = NFNL_SUBSYS_NFTABLES = 10; htons(10) = [0x00, 0x0A].
        assert_eq!(&batch[18..20], &[0x00, 0x0A], "res_id must be htons(NFNL_SUBSYS_NFTABLES=10)");
    }

    #[test]
    fn batch_flags_is_request_only() {
        let batch = build_batch(&[]);
        let flags = u16::from_le_bytes(batch[6..8].try_into().unwrap());
        assert_eq!(flags, NLM_F_REQUEST, "batch begin flags = REQUEST only");
    }
}
