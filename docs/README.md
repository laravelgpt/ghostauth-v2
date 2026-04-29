# GhostAuth v2

A comprehensive, secure, and flexible authentication package for PHP 8.3+ (backward compatible with PHP 8.2).

## 🚀 Features

### Core Authentication
- ✅ Email + Password authentication (Argon2id hashing with pepper)
- ✅ OTP authentication (Email & Phone)
- ✅ Social login (OAuth 2.0) - GitHub, Google providers included
- ✅ SSO/Single Sign-On (OIDC)
- ✅ TOTP/Google Authenticator MFA
- ✅ Passkeys/WebAuthn MFA
- ✅ Magic link authentication (passwordless)
- ✅ Concurrent session management (limit per user)
- ✅ Session rotation & fixation protection

### Security Features
- ✅ Cookie encryption (AES-256-CTR + HMAC-SHA256 signing)
- ✅ IP change cookie destroyer (invalidate all sessions on suspicious IP change)
- ✅ Device fingerprinting (IP + User-Agent + Language hash)
- ✅ Secure cookie flags (HttpOnly, Secure, SameSite=Strict)
- ✅ PSR-15 middleware for automatic protection
- ✅ JWT tokens with RS256/HS256 signing
- ✅ Token denylist for revocation (PSR-16 cache)
- ✅ Rate limiting aware (integrate with your rate limiter)
- ✅ Password strength validation (zxcvbn-inspired)
- ✅ Password breach checking (HaveIBeenPwned k-anonymity API)
- ✅ Password history (prevent reuse)
- ✅ Account lockout (brute force protection with exponential backoff)
- ✅ Trusted device management (skip MFA on trusted devices)
- ✅ Anomaly detection (impossible travel, new country, velocity checks)
- ✅ Security events & notifications (23 event types)
- ✅ Webhook dispatcher (HMAC-signed notifications to external systems)
- ✅ IP allowlist/denylist (CIDR support)
- ✅ Privacy consent management (GDPR/CCPA ready)

### Developer Experience
- ✅ PSR-4, PSR-7, PSR-11, PSR-15, PSR-16, PSR-3 compliant
- ✅ Framework agnostic (works with any PSR-7/PSR-15 app)
- ✅ Dependency injection friendly (interfaces for everything)
- ✅ Comprehensive PHPUnit test suite
- ✅ Clear separation of concerns (Strategy, Decorator, Provider patterns)
- ✅ Immutable security events
- ✅ Global event dispatcher with listeners
- ✅ Type-safe DTOs and Enums
- ✅ Full PHP 8.3+ features (readonly classes, typed constants, backed enums, json_validate)
- ✅ Graceful degradation to PHP 8.2

### Architecture
```
┌──────────────────────────────────────────────────────────────┐
│                        Your Application                        │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────────┐     ┌─────────────────┐                      │
│  │  Login      │     │ Protected       │                      │
│  │  /auth/login│     │ /dashboard      │                      │
│  │  /auth/otp  │     │ /api/users      │                      │
│  └────┬────────┘     └────┬───────────┘                      │
│       │                  │                                  │
│       ▼                  ▼                                  │
│  ┌─────────────┐    ┌─────────────────────┐                  │
│  │ AuthManager │    │ GhostAuthMiddleware │                  │
│  │  ├── PasswordProvider │  │  ├── SessionGuard   │            │
│  │  ├── OtpProvider    │  │  │  ├── CookieGuard    │            │
│  │  ├── GoogleProvider │  │  │  ├── DeviceFingerprint│         │
│  │  ├── OidcProvider   │  │  │  ├── IpGuard        │            │
│  │  └── MagicLinkProvider│  │  │  └── AccountLockout │            │
│  └────┬──────────┘    │  └─────────────────┘                  │
│       │                      │                                │
│       ▼                      ▼                                │
│  ┌─────────────┐    ┌────────────────────┐    ┌──────────────┐ │
│  │ JwtTokenSvc │    │ EventDispatcher    │    │ WebhookDisp.   │ │
│  │ (RS256/HS256)│    │ (23 event types)   │    │ (HMAC signed)  │ │
│  └─────────────┘    └────────────────────┘    └──────────────┘ │
│                                                                │
│  Cache: Redis (PSR-16)                                         │
│    ├── JWT denylist (revoked JTIs)                             │
│    ├── OTP state storage                                       │
│    ├── OAuth state tokens                                      │
│    ├── Session registry (per-user active sessions)             │
│    ├── Password history                                        │
│    ├── Account lockout tracking                                │
│    ├── Trusted devices                                         │
│    ├── Consent records                                         │
│    └── Anomaly detection history                               │
│                                                                │
│  DB: Your User table                                           │
│    ├── id, email, phone, password_hash                         │
│    ├── provider, provider_id (social/OIDC)                     │
│    ├── mfa_secret (TOTP)                                       │
│    ├── webauthn_challenge (Passkeys)                           │
│    ├── consent_version, consent_given_at                       │
│    ├── last_login_at, failed_login_count, locked_until         │
│    ├── trusted_device_fingerprint (hashed)                     │
│    └── created_at, updated_at                                  │
└──────────────────────────────────────────────────────────────┘
```

## 📦 Installation

```bash
composer require ghostauth/ghostauth
```

Requires PHP 8.2+ (PHP 8.3+ recommended for full feature set).

## 🔧 Configuration

See [CONFIGURATION.md](CONFIGURATION.md) for detailed setup instructions.

## 📚 Documentation

- [README.md](README.md) - This file
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [PROMPT.md](PROMPT.md) - AI integration guide
- [CONFIGURATION.md](CONFIGURATION.md) - Detailed configuration
- [API.md](API.md) - API reference (auto-generated)
- [SECURITY.md](SECURITY.md) - Security advisories
- [UPGRADE.md](UPGRADE.md) - Upgrade guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines

## 🛡️ Security

Please see [SECURITY.md](SECURITY.md) for details on our security policy and how to report vulnerabilities.

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## 👥 Authors

- RoBoT (laravelgpt) - Initial implementation
- OpenClaw Community - Contributions

## 🙏 Acknowledgements

- Based on work by many open-source authentication libraries
- Uses: firebase/php-jwt, paragonie/constant_time_encoding, web-auth/webauthn-lib
- Inspired by: Laravel Fortify, Symfony Security, Devise (Rails)
