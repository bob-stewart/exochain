//! Authentication middleware — JWT, OAuth 2.0, SAML support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Authentication errors.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("User not found")]
    UserNotFound,
    #[error("Provider error: {0}")]
    ProviderError(String),
}

/// Authentication provider types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthProvider {
    /// JWT-based authentication.
    Jwt,
    /// OAuth 2.0.
    OAuth2 { provider: String },
    /// SAML for enterprise SSO.
    Saml { idp_entity_id: String },
    /// API key authentication.
    ApiKey,
}

/// An authenticated user session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub tenant_id: Uuid,
    pub did: String,
    pub roles: Vec<String>,
    pub auth_provider: AuthProvider,
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl AuthenticatedUser {
    /// Check if the session is still valid.
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    /// Check if the user has a specific role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// A JWT auth token (simplified).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub token_type: String,
    pub expires_in_seconds: u64,
    pub refresh_token: Option<String>,
}

/// JWT payload claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JwtPayload {
    sub: String,
    tenant_id: String,
    iss: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    token_type: String,
}

/// JWT token service using BLAKE3-HMAC signing.
pub struct JwtService {
    issuer: String,
    default_ttl_seconds: u64,
    secret: Vec<u8>,
}

impl JwtService {
    pub fn new(issuer: String, default_ttl_seconds: u64) -> Self {
        Self {
            issuer,
            default_ttl_seconds,
            secret: b"default-dev-secret-do-not-use-in-prod".to_vec(),
        }
    }

    /// Create a JwtService with a specific signing secret.
    pub fn with_secret(issuer: String, default_ttl_seconds: u64, secret: Vec<u8>) -> Self {
        Self {
            issuer,
            default_ttl_seconds,
            secret,
        }
    }

    /// Compute BLAKE3-HMAC: BLAKE3(secret || payload_json)
    fn compute_signature(&self, payload_json: &str) -> String {
        let mut preimage = Vec::with_capacity(self.secret.len() + payload_json.len());
        preimage.extend_from_slice(&self.secret);
        preimage.extend_from_slice(payload_json.as_bytes());
        let hash = exo_core::hash_bytes(&preimage);
        hex::encode(hash.0)
    }

    /// Issue a new token for an authenticated user.
    pub fn issue_token(&self, user: &AuthenticatedUser) -> AuthToken {
        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(self.default_ttl_seconds as i64);

        let payload = JwtPayload {
            sub: user.user_id.clone(),
            tenant_id: user.tenant_id.to_string(),
            iss: self.issuer.clone(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            token_type: "access".to_string(),
        };

        let payload_json = serde_json::to_string(&payload).expect("serialize JWT payload");
        let payload_hex = hex::encode(payload_json.as_bytes());
        let sig = self.compute_signature(&payload_json);
        let token = format!("{}.{}", payload_hex, sig);

        // Issue refresh token
        let refresh_payload = JwtPayload {
            sub: user.user_id.clone(),
            tenant_id: user.tenant_id.to_string(),
            iss: self.issuer.clone(),
            iat: now.timestamp(),
            exp: (now + chrono::Duration::seconds(self.default_ttl_seconds as i64 * 24)).timestamp(),
            token_type: "refresh".to_string(),
        };
        let refresh_json = serde_json::to_string(&refresh_payload).expect("serialize refresh payload");
        let refresh_hex = hex::encode(refresh_json.as_bytes());
        let refresh_sig = self.compute_signature(&refresh_json);
        let refresh_token = format!("{}.{}", refresh_hex, refresh_sig);

        AuthToken {
            token,
            token_type: "Bearer".into(),
            expires_in_seconds: self.default_ttl_seconds,
            refresh_token: Some(refresh_token),
        }
    }

    /// Validate a token and return claims.
    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, AuthError> {
        // Split on '.'
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidToken);
        }

        // Decode payload from hex
        let payload_bytes = hex::decode(parts[0]).map_err(|_| AuthError::InvalidToken)?;
        let payload_json =
            String::from_utf8(payload_bytes).map_err(|_| AuthError::InvalidToken)?;

        // Recompute signature and verify
        let expected_sig = self.compute_signature(&payload_json);
        if parts[1] != expected_sig {
            return Err(AuthError::InvalidToken);
        }

        // Parse payload
        let payload: JwtPayload =
            serde_json::from_str(&payload_json).map_err(|_| AuthError::InvalidToken)?;

        // Check issuer
        if payload.iss != self.issuer {
            return Err(AuthError::InvalidToken);
        }

        // Check expiry
        let now = Utc::now().timestamp();
        if payload.exp <= now {
            return Err(AuthError::TokenExpired);
        }

        Ok(TokenClaims {
            user_id: payload.sub,
            tenant_id: payload.tenant_id,
            issuer: payload.iss,
        })
    }
}

/// Decoded JWT claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub user_id: String,
    pub tenant_id: String,
    pub issuer: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> AuthenticatedUser {
        AuthenticatedUser {
            user_id: "user-1".into(),
            tenant_id: Uuid::new_v4(),
            did: "did:exo:alice".into(),
            roles: vec!["admin".into(), "voter".into()],
            auth_provider: AuthProvider::Jwt,
            authenticated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    #[test]
    fn test_user_session_validity() {
        let user = test_user();
        assert!(user.is_valid());
        assert!(user.has_role("admin"));
        assert!(!user.has_role("superadmin"));
    }

    #[test]
    fn test_jwt_issue_and_validate() {
        let service = JwtService::new("decision.forum".into(), 3600);
        let user = test_user();
        let token = service.issue_token(&user);

        assert_eq!(token.token_type, "Bearer");
        let claims = service.validate_token(&token.token).unwrap();
        assert_eq!(claims.user_id, "user-1");
    }

    #[test]
    fn test_invalid_token() {
        let service = JwtService::new("decision.forum".into(), 3600);
        assert!(service.validate_token("bad-token").is_err());
    }

    #[test]
    fn test_token_roundtrip() {
        let secret = b"test-secret-key-12345".to_vec();
        let service = JwtService::with_secret("exochain.test".into(), 7200, secret);
        let user = test_user();
        let token = service.issue_token(&user);

        let claims = service.validate_token(&token.token).unwrap();
        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.issuer, "exochain.test");
        assert_eq!(claims.tenant_id, user.tenant_id.to_string());
    }

    #[test]
    fn test_expired_token_rejection() {
        // Create a service with 0-second TTL so token is immediately expired
        let service = JwtService::new("decision.forum".into(), 0);
        let user = test_user();
        let token = service.issue_token(&user);

        // Token should be expired (exp <= now)
        let result = service.validate_token(&token.token);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::TokenExpired => {} // expected
            other => panic!("Expected TokenExpired, got: {:?}", other),
        }
    }

    #[test]
    fn test_tampered_token_rejection() {
        let service = JwtService::new("decision.forum".into(), 3600);
        let user = test_user();
        let token = service.issue_token(&user);

        // Tamper with the payload (change a byte in the hex-encoded payload)
        let parts: Vec<&str> = token.token.split('.').collect();
        let mut tampered_payload = parts[0].to_string();
        // Replace first character to tamper
        let replacement = if tampered_payload.starts_with('a') {
            "b"
        } else {
            "a"
        };
        tampered_payload.replace_range(0..1, replacement);
        let tampered_token = format!("{}.{}", tampered_payload, parts[1]);

        let result = service.validate_token(&tampered_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_issuer_rejection() {
        let secret = b"shared-secret".to_vec();
        let service_a = JwtService::with_secret("issuer-a".into(), 3600, secret.clone());
        let service_b = JwtService::with_secret("issuer-b".into(), 3600, secret);
        let user = test_user();
        let token = service_a.issue_token(&user);

        // service_b has same secret but different issuer — should reject
        // Actually the signature will differ because the payload contains different issuer...
        // But the token was issued by service_a, so payload has issuer-a.
        // service_b will recompute the same signature (same secret, same payload)
        // but then check issuer != "issuer-b" and reject.
        let result = service_b.validate_token(&token.token);
        assert!(result.is_err());
    }

    #[test]
    fn test_refresh_token_is_valid() {
        let service = JwtService::new("decision.forum".into(), 3600);
        let user = test_user();
        let token = service.issue_token(&user);

        // Refresh token should also be validatable
        let refresh = token.refresh_token.expect("should have refresh token");
        let claims = service.validate_token(&refresh).unwrap();
        assert_eq!(claims.user_id, "user-1");
    }
}
