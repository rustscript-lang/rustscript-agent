//! Cryptographically random PKCE S256 primitives.
//!
//! Verifier bytes stay host-side. The public surface is the S256 challenge
//! string and the challenge method label.

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

const VERIFIER_BYTES: usize = 32;
const STATE_BYTES: usize = 16;

/// RFC 7636 S256 method label.
pub const PKCE_CHALLENGE_METHOD: &str = "S256";

/// PKCE generation or challenge failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PkceError {
    /// The platform CSPRNG refused to fill the requested buffer.
    EntropyUnavailable,
    /// The verifier is empty, oversized, or not RFC 7636 unreserved ASCII.
    InvalidVerifier,
}

impl PkceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EntropyUnavailable => "pkce_entropy",
            Self::InvalidVerifier => "pkce_invalid_verifier",
        }
    }
}

impl std::fmt::Display for PkceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntropyUnavailable => formatter.write_str("PKCE CSPRNG is unavailable"),
            Self::InvalidVerifier => formatter.write_str("PKCE verifier is invalid"),
        }
    }
}

impl std::error::Error for PkceError {}

/// Host-owned PKCE verifier. Debug is redacted and the allocation is zeroized.
pub struct PkceVerifier(Zeroizing<String>);

impl PkceVerifier {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PkceVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PkceVerifier")
    }
}

/// Host-owned OAuth `state` value. Debug is redacted.
pub struct PkceState(String);

impl PkceState {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PkceState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PkceState")
    }
}

/// Fresh S256 verifier, matching challenge, and CSRF state.
pub struct PkceMaterial {
    /// RFC 7636 S256 challenge (base64url, no padding).
    pub challenge: String,
    verifier: PkceVerifier,
    state: PkceState,
}

impl PkceMaterial {
    pub(crate) fn into_parts(self) -> (String, PkceVerifier, PkceState) {
        (self.challenge, self.verifier, self.state)
    }
}

impl std::fmt::Debug for PkceMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PkceMaterial")
            .field("challenge", &self.challenge)
            .field("method", &PKCE_CHALLENGE_METHOD)
            .finish_non_exhaustive()
    }
}

/// Generates a random S256 verifier/challenge pair and a random `state`.
pub fn generate() -> Result<PkceMaterial, PkceError> {
    let verifier = random_base64url(VERIFIER_BYTES)?;
    let state = random_base64url(STATE_BYTES)?;
    let challenge = s256_challenge(&verifier)?;
    Ok(PkceMaterial {
        challenge,
        verifier: PkceVerifier(Zeroizing::new(verifier)),
        state: PkceState(state),
    })
}

/// RFC 7636 S256 challenge: BASE64URL-ENCODE(SHA256(verifier)).
pub fn s256_challenge(verifier: &str) -> Result<String, PkceError> {
    if verifier.len() < 43 || verifier.len() > 128 || !is_unreserved(verifier) {
        return Err(PkceError::InvalidVerifier);
    }
    let digest = digest(&SHA256, verifier.as_bytes());
    Ok(base64url_nopad(digest.as_ref()))
}

fn random_base64url(nbytes: usize) -> Result<String, PkceError> {
    let mut bytes = vec![0u8; nbytes];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| PkceError::EntropyUnavailable)?;
    Ok(base64url_nopad(&bytes))
}

fn is_unreserved(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
            )
        })
}

fn base64url_nopad(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        index += 3;
    }
    match bytes.len() - index {
        1 => {
            let n = u32::from(bytes[index]) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
        2 => {
            let n = (u32::from(bytes[index]) << 16) | (u32::from(bytes[index + 1]) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b() {
        let challenge =
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").expect("vector");
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
}
