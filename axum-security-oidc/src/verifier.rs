use std::fmt;

use base64::Engine as _;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet},
};
use subtle::ConstantTimeEq as _;

use crate::{
    claims::OidcClaims,
    error::{ClaimsError, VerifyError},
};

/// The default signing-algorithm allow-list: the asymmetric algorithms real
/// OIDC providers sign ID tokens with. Notably excludes `none` (rejected
/// categorically) and the symmetric `HS*` family (which would need the client
/// secret as the key rather than a JWK). `ES512`/P-521 is unsupported upstream
/// (`jsonwebtoken` has no variant for it).
const DEFAULT_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// The clock-skew allowance, in seconds, applied to `exp`/`nbf` checks.
const DEFAULT_LEEWAY_SECS: u64 = 60;

/// Verifies OpenID Connect ID tokens against a JWK set.
///
/// Given a JWKS and a token, [`verify`](IdTokenVerifier::verify) checks the
/// signature (with algorithm allow-listing), the `iss`/`aud`/`exp`/`nbf`
/// claims, and the `nonce`, then hands back a [`VerifiedIdToken`] whose
/// [`claims`](VerifiedIdToken::claims) expose the standard claim set.
///
/// This type does no I/O: the JWKS is supplied up front. Fetching, caching, and
/// key rotation are layered on top (a later phase).
#[derive(Debug)]
pub struct IdTokenVerifier {
    issuer: String,
    audience: String,
    algorithms: Vec<Algorithm>,
    leeway_secs: u64,
    jwks: JwkSet,
}

impl IdTokenVerifier {
    /// A verifier for tokens from `issuer`, addressed to `audience` (the client
    /// id), signed by a key in `jwks`.
    ///
    /// Defaults to the asymmetric algorithm allow-list (RS/PS 256-512, ES256,
    /// ES384, EdDSA) and a 60-second clock-skew leeway; narrow either with
    /// [`algorithms`](Self::algorithms) / [`leeway_secs`](Self::leeway_secs).
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, jwks: JwkSet) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: DEFAULT_ALGORITHMS.to_vec(),
            leeway_secs: DEFAULT_LEEWAY_SECS,
            jwks,
        }
    }

    /// Restrict the accepted signing algorithms. A token whose `alg` header is
    /// not in this list is rejected with [`VerifyError::AlgorithmNotAllowed`].
    pub fn algorithms(mut self, algorithms: &[Algorithm]) -> Self {
        self.algorithms = algorithms.to_vec();
        self
    }

    /// Set the clock-skew leeway (seconds) applied to `exp`/`nbf`.
    pub fn leeway_secs(mut self, leeway_secs: u64) -> Self {
        self.leeway_secs = leeway_secs;
        self
    }

    /// Verify `id_token` and check its `nonce` against `nonce`.
    ///
    /// On success the token's signature, issuer, audience, expiry, and nonce
    /// have all been checked.
    pub fn verify(&self, id_token: &str, nonce: &str) -> Result<VerifiedIdToken, VerifyError> {
        let header = decode_header(id_token).map_err(|_| VerifyError::MalformedToken)?;

        // Never trust the token's own `alg`: reject anything outside the
        // allow-list before we even select a key.
        if !self.algorithms.contains(&header.alg) {
            return Err(VerifyError::AlgorithmNotAllowed);
        }

        let jwk = self.select_key(header.kid.as_deref())?;
        let key = DecodingKey::from_jwk(jwk).map_err(|_| VerifyError::InvalidKey)?;

        // The allow-list check above is the real guard against algorithm
        // confusion; here we hand jsonwebtoken exactly the (vetted) header alg.
        // A mixed-family list would make `decode` reject with `InvalidAlgorithm`,
        // and it also can't cross families — an RS256-header token verified
        // against this RSA key can't be an HS256/ES256 substitution.
        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.leeway = self.leeway_secs;
        validation.validate_exp = true;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        // Signature + iss + aud + exp/nbf, in one call.
        let data = decode::<NonceClaim>(id_token, &key, &validation).map_err(map_jwt_error)?;

        // Nonce is OIDC-specific — jsonwebtoken has no concept of it. Compare in
        // constant time; an absent token nonce compares against "" and fails.
        let token_nonce = data.claims.nonce.unwrap_or_default();
        if !bool::from(token_nonce.as_bytes().ct_eq(nonce.as_bytes())) {
            return Err(VerifyError::NonceMismatch);
        }

        let payload = decode_payload(id_token)?;
        Ok(VerifiedIdToken {
            id_token: id_token.to_owned(),
            payload,
        })
    }

    /// Select the verification key by `kid`. A token with no `kid` is only
    /// accepted when the JWKS holds exactly one key.
    fn select_key(&self, kid: Option<&str>) -> Result<&Jwk, VerifyError> {
        match kid {
            Some(kid) => self.jwks.find(kid).ok_or(VerifyError::UnknownKey),
            None => match self.jwks.keys.as_slice() {
                [only] => Ok(only),
                _ => Err(VerifyError::UnknownKey),
            },
        }
    }
}

/// A successfully verified ID token.
///
/// Holds the raw JWT (for use as an `id_token_hint` on logout) and the decoded
/// payload; [`claims`](Self::claims) deserializes the standard claim set on
/// demand.
pub struct VerifiedIdToken {
    id_token: String,
    payload: Vec<u8>,
}

impl VerifiedIdToken {
    /// The raw ID token JWT.
    pub fn id_token(&self) -> &str {
        &self.id_token
    }

    /// The standard claim set, borrowing from the decoded payload.
    pub fn claims(&self) -> Result<OidcClaims<'_>, ClaimsError> {
        OidcClaims::from_payload(&self.payload)
    }
}

impl fmt::Debug for VerifiedIdToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The raw JWT is a bearer credential; keep it out of logs.
        f.debug_struct("VerifiedIdToken")
            .field("id_token", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// The only OIDC-specific claim `jsonwebtoken` won't check for us.
#[derive(serde::Deserialize)]
struct NonceClaim {
    #[serde(default)]
    nonce: Option<String>,
}

/// Decode the JWT payload (second segment) from base64url.
fn decode_payload(token: &str) -> Result<Vec<u8>, VerifyError> {
    let payload = token.split('.').nth(1).ok_or(VerifyError::MalformedToken)?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| VerifyError::MalformedToken)
}

fn map_jwt_error(err: jsonwebtoken::errors::Error) -> VerifyError {
    use jsonwebtoken::errors::ErrorKind;
    match err.kind() {
        ErrorKind::InvalidSignature => VerifyError::SignatureInvalid,
        ErrorKind::InvalidIssuer => VerifyError::IssuerMismatch,
        ErrorKind::InvalidAudience => VerifyError::AudienceMismatch,
        ErrorKind::ExpiredSignature => VerifyError::Expired,
        ErrorKind::ImmatureSignature => VerifyError::ImmatureToken,
        ErrorKind::InvalidAlgorithm => VerifyError::AlgorithmNotAllowed,
        _ => VerifyError::InvalidToken,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::{Value, json};

    use super::*;

    const KID: &str = "test-key";
    const ISSUER: &str = "https://issuer.example";
    const AUDIENCE: &str = "test-client-id";

    // A 2048-bit RSA test key pair, generated once for these tests. `N` is the
    // public modulus (base64url) — it lives in the JWKS below; the private key
    // signs tokens. Both are in `testdata/` (base64 blobs the typos checker
    // would otherwise flag as misspellings).
    const N: &str = include_str!("testdata/rsa_modulus_b64u.txt");
    const PRIV_PEM: &str = include_str!("testdata/rsa_priv_pem.txt");

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Build a JWKS holding the test public key under `kid`, with modulus `n`.
    fn jwks_with(kid: &str, n: &str) -> JwkSet {
        let json = format!(
            r#"{{"keys":[{{"kty":"RSA","use":"sig","kid":"{kid}","alg":"RS256","n":"{n}","e":"AQAB"}}]}}"#
        );
        serde_json::from_str(&json).expect("valid JWKS")
    }

    fn jwks() -> JwkSet {
        jwks_with(KID, N)
    }

    /// Sign `claims` with the test private key under header `kid`.
    fn sign(claims: &Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        let key = EncodingKey::from_rsa_pem(PRIV_PEM.as_bytes()).expect("valid PEM");
        encode(&header, claims, &key).expect("encode")
    }

    fn claims(nonce: &str, aud: &str, exp: u64) -> Value {
        json!({
            "iss": ISSUER,
            "aud": aud,
            "sub": "user-123",
            "exp": exp,
            "iat": now(),
            "nonce": nonce,
            "email": "user@example.com",
            "email_verified": true,
            "hd": "example.com",
        })
    }

    fn valid_token(nonce: &str) -> String {
        sign(&claims(nonce, AUDIENCE, now() + 3600), KID)
    }

    #[test]
    fn verifies_a_valid_token() {
        let verifier = IdTokenVerifier::new(ISSUER, AUDIENCE, jwks());
        let verified = verifier
            .verify(&valid_token("the-nonce"), "the-nonce")
            .unwrap();

        let claims = verified.claims().unwrap();
        assert_eq!(claims.issuer, ISSUER);
        assert_eq!(claims.subject, "user-123");
        assert_eq!(claims.audiences, ["test-client-id"]);
        assert_eq!(claims.email, Some("user@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        // Non-standard claims land in `extra`.
        assert_eq!(
            claims.extra.get("hd").and_then(Value::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn rejects_wrong_nonce() {
        let verifier = IdTokenVerifier::new(ISSUER, AUDIENCE, jwks());
        let err = verifier
            .verify(&valid_token("the-nonce"), "other-nonce")
            .unwrap_err();
        assert!(matches!(err, VerifyError::NonceMismatch), "{err:?}");
    }

    #[test]
    fn rejects_wrong_audience() {
        // Token minted for a different client id.
        let token = sign(&claims("n", "some-other-client", now() + 3600), KID);
        let verifier = IdTokenVerifier::new(ISSUER, AUDIENCE, jwks());
        let err = verifier.verify(&token, "n").unwrap_err();
        assert!(matches!(err, VerifyError::AudienceMismatch), "{err:?}");
    }

    #[test]
    fn rejects_wrong_issuer() {
        let verifier = IdTokenVerifier::new("https://attacker.example", AUDIENCE, jwks());
        let err = verifier.verify(&valid_token("n"), "n").unwrap_err();
        assert!(matches!(err, VerifyError::IssuerMismatch), "{err:?}");
    }

    #[test]
    fn rejects_expired_token() {
        // exp two minutes ago — outside the 60s default leeway.
        let token = sign(&claims("n", AUDIENCE, now() - 120), KID);
        let verifier = IdTokenVerifier::new(ISSUER, AUDIENCE, jwks());
        let err = verifier.verify(&token, "n").unwrap_err();
        assert!(matches!(err, VerifyError::Expired), "{err:?}");
    }

    #[test]
    fn rejects_unknown_kid() {
        // Token signed under a kid absent from the JWKS.
        let token = sign(&claims("n", AUDIENCE, now() + 3600), "rotated-away");
        let verifier = IdTokenVerifier::new(ISSUER, AUDIENCE, jwks());
        let err = verifier.verify(&token, "n").unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKey), "{err:?}");
    }

    #[test]
    fn rejects_disallowed_algorithm() {
        // Verifier only accepts ES256; the token is RS256.
        let verifier =
            IdTokenVerifier::new(ISSUER, AUDIENCE, jwks()).algorithms(&[Algorithm::ES256]);
        let err = verifier.verify(&valid_token("n"), "n").unwrap_err();
        assert!(matches!(err, VerifyError::AlgorithmNotAllowed), "{err:?}");
    }

    #[test]
    fn rejects_bad_signature() {
        // Same kid, but the JWKS modulus is mutated: a structurally valid key
        // that the signature won't verify against.
        let wrong_n = format!("y{}", &N[1..]);
        let verifier = IdTokenVerifier::new(ISSUER, AUDIENCE, jwks_with(KID, &wrong_n));
        let err = verifier.verify(&valid_token("n"), "n").unwrap_err();
        assert!(matches!(err, VerifyError::SignatureInvalid), "{err:?}");
    }

    #[test]
    fn rejects_malformed_token() {
        let verifier = IdTokenVerifier::new(ISSUER, AUDIENCE, jwks());
        let err = verifier.verify("not-a-jwt", "n").unwrap_err();
        assert!(matches!(err, VerifyError::MalformedToken), "{err:?}");
    }

    #[test]
    fn debug_redacts_raw_token() {
        let verifier = IdTokenVerifier::new(ISSUER, AUDIENCE, jwks());
        let token = valid_token("n");
        let verified = verifier.verify(&token, "n").unwrap();
        let debug = format!("{verified:?}");
        assert!(!debug.contains(&token), "{debug}");
        assert!(debug.contains("[redacted]"), "{debug}");
    }
}
