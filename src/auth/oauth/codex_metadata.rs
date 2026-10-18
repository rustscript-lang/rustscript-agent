use super::{OAuthError, parse_strict_json};

const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const ACCOUNT_NAMESPACE: &str = "https://api.openai.com/auth";
const ACCOUNT_CLAIM: &str = "chatgpt_account_id";
const FLATTENED_ALTERNATE_CLAIM: &str = "https://api.openai.com/auth.chatgpt_account_id";

/// Reads only the routing claim from the exact access token used for Authorization.
/// It does not verify a JWT signature and never returns the token or parse text.
pub(super) fn account_id_from_access_token(token: &str) -> Result<String, OAuthError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(OAuthError::CodexMetadataInvalid);
    }
    let mut parts = token.split('.');
    let header = parts.next().ok_or(OAuthError::CodexMetadataInvalid)?;
    let payload = parts.next().ok_or(OAuthError::CodexMetadataInvalid)?;
    let signature = parts.next().ok_or(OAuthError::CodexMetadataInvalid)?;
    if parts.next().is_some()
        || header.is_empty()
        || payload.is_empty()
        || signature.is_empty()
        || ![header, payload, signature]
            .into_iter()
            .all(is_compact_segment)
    {
        return Err(OAuthError::CodexMetadataInvalid);
    }

    let payload = decode_base64url(payload).ok_or(OAuthError::CodexMetadataInvalid)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(OAuthError::CodexMetadataInvalid);
    }
    let payload = std::str::from_utf8(&payload).map_err(|_| OAuthError::CodexMetadataInvalid)?;
    let parsed = parse_strict_json(payload).map_err(|_| OAuthError::CodexMetadataInvalid)?;
    let root = parsed.as_object().ok_or(OAuthError::CodexMetadataInvalid)?;
    let Some(namespace) = root.get(ACCOUNT_NAMESPACE) else {
        return Err(OAuthError::CodexMetadataUnavailable);
    };
    let namespace = namespace
        .as_object()
        .ok_or(OAuthError::CodexMetadataInvalid)?;
    let Some(value) = namespace.get(ACCOUNT_CLAIM) else {
        return Err(OAuthError::CodexMetadataUnavailable);
    };
    let account_id = value.as_str().ok_or(OAuthError::CodexMetadataInvalid)?;
    if !valid_account_id(account_id) {
        return Err(OAuthError::CodexMetadataInvalid);
    }
    if let Some(alternate) = root.get(FLATTENED_ALTERNATE_CLAIM) {
        let alternate = alternate.as_str().ok_or(OAuthError::CodexMetadataInvalid)?;
        if !valid_account_id(alternate) {
            return Err(OAuthError::CodexMetadataInvalid);
        }
        if alternate != account_id {
            return Err(OAuthError::CodexMetadataConflict);
        }
    }
    Ok(account_id.to_string())
}

fn valid_account_id(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() <= 128
        && account_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_compact_segment(segment: &str) -> bool {
    segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 4 == 1 {
        return None;
    }
    let output_len = input.len().checked_mul(3)?.checked_div(4)?;
    if output_len > MAX_PAYLOAD_BYTES {
        return None;
    }
    let mut output = Vec::with_capacity(output_len);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1u32 << bits).wrapping_sub(1);
        }
    }
    (accumulator == 0 && output.len() <= MAX_PAYLOAD_BYTES).then_some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn encode_base64url(input: &[u8]) -> String {
        let mut output = String::new();
        for chunk in input.chunks(3) {
            let first = u32::from(chunk[0]);
            let second = u32::from(chunk.get(1).copied().unwrap_or(0));
            let third = u32::from(chunk.get(2).copied().unwrap_or(0));
            let value = (first << 16) | (second << 8) | third;
            output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
            output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[(value & 63) as usize] as char);
            }
        }
        output
    }

    fn token(payload: &str) -> String {
        format!("e30.{}.AA", encode_base64url(payload.as_bytes()))
    }

    #[test]
    fn reads_only_bounded_access_claim() {
        let payload =
            format!(r#"{{"{ACCOUNT_NAMESPACE}":{{"{ACCOUNT_CLAIM}":"acct_fixture-1"}}}}"#);
        assert_eq!(
            account_id_from_access_token(&token(&payload)).expect("account claim"),
            "acct_fixture-1"
        );
    }

    #[test]
    fn flat_only_claim_is_not_a_canonical_source() {
        let flat = token(&format!(
            r#"{{"{FLATTENED_ALTERNATE_CLAIM}":"acct_fixture-1"}}"#
        ));
        assert_eq!(
            account_id_from_access_token(&flat),
            Err(OAuthError::CodexMetadataUnavailable)
        );
    }

    #[test]
    fn conflicting_flat_alternate_is_rejected() {
        let conflict = token(&format!(
            r#"{{"{ACCOUNT_NAMESPACE}":{{"{ACCOUNT_CLAIM}":"acct_canonical"}},"{FLATTENED_ALTERNATE_CLAIM}":"acct_alternate"}}"#
        ));
        assert_eq!(
            account_id_from_access_token(&conflict),
            Err(OAuthError::CodexMetadataConflict)
        );
    }

    #[test]
    fn missing_claim_is_unavailable_and_duplicate_claim_is_invalid() {
        let missing = token("{}");
        assert_eq!(
            account_id_from_access_token(&missing),
            Err(OAuthError::CodexMetadataUnavailable)
        );
        let duplicate = token(&format!(
            r#"{{"{ACCOUNT_NAMESPACE}":{{"{ACCOUNT_CLAIM}":"one","{ACCOUNT_CLAIM}":"two"}}}}"#
        ));
        assert_eq!(
            account_id_from_access_token(&duplicate),
            Err(OAuthError::CodexMetadataInvalid)
        );
    }

    #[test]
    fn rejects_malformed_segments_and_account_values_without_echoing_them() {
        assert_eq!(
            account_id_from_access_token("e30.abc$.AA"),
            Err(OAuthError::CodexMetadataInvalid)
        );
        let invalid = token(&format!(
            r#"{{"{ACCOUNT_NAMESPACE}":{{"{ACCOUNT_CLAIM}":"acct:value"}}}}"#
        ));
        assert_eq!(
            account_id_from_access_token(&invalid),
            Err(OAuthError::CodexMetadataInvalid)
        );
    }

    #[test]
    fn rejects_oversized_token_before_decoding() {
        let token = format!("e30.{}.AA", "A".repeat(MAX_TOKEN_BYTES));
        assert_eq!(
            account_id_from_access_token(&token),
            Err(OAuthError::CodexMetadataInvalid)
        );
    }

    #[test]
    fn parsed_payload_is_strict_json() {
        let duplicate_claim = token(&format!(
            r#"{{"{ACCOUNT_NAMESPACE}":{{"{ACCOUNT_CLAIM}":"one","{ACCOUNT_CLAIM}":"two"}}}}"#
        ));
        assert_eq!(
            account_id_from_access_token(&duplicate_claim),
            Err(OAuthError::CodexMetadataInvalid)
        );
        let duplicate_namespace = token(&format!(
            r#"{{"{ACCOUNT_NAMESPACE}":{{"{ACCOUNT_CLAIM}":"one"}},"{ACCOUNT_NAMESPACE}":{{"{ACCOUNT_CLAIM}":"two"}}}}"#
        ));
        assert_eq!(
            account_id_from_access_token(&duplicate_namespace),
            Err(OAuthError::CodexMetadataInvalid)
        );
    }
}
