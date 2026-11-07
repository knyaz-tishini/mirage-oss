//! The credential the leg presents.
//!
//! The scheme itself lives in `mirage_core::crypto::credential::role_signed`:
//! two signatures — an operator/group-signed identity excerpt, minted once by
//! the operator and held by the box; and a per-dial signature by the same
//! slice's own signing key, bound to the dialled exit's node id plus a fresh
//! nonce and timestamp.
//!
//! Minting is cheap and synchronous — two fixed-size preimages — so it happens
//! on the dial, and the excerpt is what is held.

use mirage_core::capsule::RoleSlice;
use mirage_core::crypto::credential::role_signed::{
    mint_role_signed_token, RoleSignedError, RoleSignedIdentityExcerpt,
};
use mirage_core::mirage::wire::credential_scheme::CredentialScheme;
use mirage_protocol::driver::ClientCredential;

/// Mint the credential for one dial.
///
/// The token is bound to `exit_node_id`: a leg that is replayed at a different
/// box does not verify there.
pub fn mint_credential(
    slice: &RoleSlice,
    excerpt: &RoleSignedIdentityExcerpt,
    exit_node_id: &str,
    now_ms: u64,
) -> Result<ClientCredential, RoleSignedError> {
    let token = mint_role_signed_token(slice, excerpt, exit_node_id, now_ms)?;
    let bytes = token.encode()?;
    Ok(ClientCredential {
        scheme: CredentialScheme::RoleSigned.as_u8(),
        token: bytes,
    })
}
