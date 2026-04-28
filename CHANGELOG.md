# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-04-28

### Added
- Comprehensive authentication system with multiple strategies
- Email + Password (Argon2id + pepper)
- OTP authentication (Email & Phone providers)
- Social login (GitHub, Google OAuth2)
- SSO/OIDC support
- TOTP/Google Authenticator MFA
- Passkeys/WebAuthn MFA
- Magic link authentication
- Concurrent session management & session rotation
- Cookie encryption (AES-256-CTR + HMAC-SHA256)
- IP change cookie destroyer
- Device fingerprinting
- PSR-15 middleware
- JWT tokens with RS256/HS256 + denylist revocation
- Rate limiting awareness
- Trusted device management
- Account lockout (brute force protection)
- Password strength validation (zxcvbn-inspired)
- Password breach checking (HIBP k-anonymity)
- Email verification flow
- Password reset flow
- IP allowlist/denylist (CIDR support)
- Anomaly detection (impossible travel, new country, velocity)
- Security event system (23 event types)
- Global event dispatcher with listeners
- Webhook dispatcher (HMAC-signed)
- Password history (prevent reuse)
- Privacy consent management (GDPR/CCPA)
- RBAC (Role-Based Access Control)
- PHP 8.3+ features (readonly classes, typed constants, backed enums)
- Full PSR compliance (PSR-4,7,11,15,16,3)
- Framework agnostic design
- Comprehensive test suite
- Detailed documentation

### Changed
- Nothing (initial release)

### Deprecated
- Nothing (initial release)

### Removed
- Nothing (initial release)

### Fixed
- Nothing (initial release)

### Security
- Initial secure release
