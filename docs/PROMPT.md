# PROMPT.md — GhostAuth Integration Guide

> How to integrate GhostAuth into your project. Use this as your master prompt for AI coding agents, developers, and project setup.

---

## Quick Copy Prompt

Paste this into any coding agent to scaffold a full GhostAuth integration:

```
Integrate GhostAuth v2 into my project with the following requirements:
1. Cookie-encrypted sessions with AES-256-CTR + HMAC-SHA256 signing
2. IP change cookie destroyer — invalidate ALL sessions when IP/device changes
3. Device fingerprinting (IP + User-Agent binding)
4. Session rotation on every request (prevent session fixation)
5. Concurrent session limit: max 5 per user
6. Secure cookie flags: HttpOnly, Secure, SameSite=Strict
7. PSR-15 middleware for all protected routes
8. Excluded paths: /auth/login, /auth/otp/send, /auth/otp/verify, /health
9. Password hashing: Argon2id with pepper from .env
10. JWT tokens: RS256 with denylist revocation via Redis

Use GhostAuthConfiguration::fromArray(), AuthManager, SessionGuard,
GhostAuthMiddleware, and DeviceFingerprint. All config from .env file.
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                        Your Application                        │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────────┐     ┌─────────────────┐                  │
│  │  Login Route    │     │ Protected Route  │                  │
│  │  /auth/login    │     │ /dashboard        │                  │
│  │  /auth/otp      │     │ /api/users        │                  │
│  └────┬────────────┘     └────────┬──────────┘                  │
│       │                           │                              │
│       ▼                           ▼                              │
│  ┌─────────────┐          ┌─────────────────────┐              │
│  │ AuthManager │          │ GhostAuthMiddleware  │              │
│  │  └── PasswordProvider│  │  └── SessionGuard   │              │
│  │  └── OtpProvider     │  │      └── Cookie     │              │
│  │  └── GoogleProvider  │  │      └── Fingerprint│              │
│  │  └── OidcProvider    │  │      └── IP Destroy │              │
│  └────┬──────────┘      └────┬────────────┘     │              │
│       │                       │                  │              │
│       ▼                       ▼                  │              │
│  ┌─────────────┐     ┌────────────────────┐     │              │
│  │ JwtTokenSvc │     │ DeviceFingerprint   │     │              │
│  │ (RS256/HS256)│     │ (IP+UA+Lang hash)  │     │              │
│  └─────────────┘     └────────────────────┘     │              │
│                                                    │              │
│  Cache: Redis (PSR-16)                             │              │
│    ├── JWT denylist (revoked JTIs)                 │              │
│    ├── OTP HMAC storage                            │              │
│    ├── OAuth state tokens                          │              │
│    └── Session registry (per-user active sessions) │              │
│                                                    │              │
│  DB: Your User table                               │              │
│    ├── id, email, phone, password_hash             │              │
│    ├── provider, provider_id (for social)          │              │
│    ├── mfa_secret (for TOTP)                       │              │
│    └── created_at, updated_at, last_login_at       │              │
└────────────────────────────────────────────────────┘
```

---

## Step 1: Environment Variables

Add to your `.env`:

```env
# ── App ──
APP_NAME=MyApp
APP_URL=https://myapp.com
API_URL=https://api.myapp.com

# ── JWT (RS256 recommended for production) ──
JWT_ALGO=HS256
JWT_SECRET=change-me-to-64-random-characters-minimum-please!!
JWT_TTL=3600
JWT_PUBLIC_KEY=/secrets/jwt-public.pem   # Only if JWT_ALGO=RS256
JWT_PRIVATE_KEY=/secrets/jwt-private.pem # Only if JWT_ALGO=RS256

# ── Password Pepper ──
PASSWORD_PEPPER=another-64-char-secret-for-hashing-passwords!!

# ── OTP ──
OTP_HMAC_SECRET=32-byte-hmac-secret-for-otp-storage!!

# ── Session Cookie ──
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_DOMAIN=myapp.com
SESSION_MAX_PER_USER=5
SESSION_STRICT_IP=true

# ── Device Fingerprint ──
FINGERPRINT_SALT=fingerprint-salt-for-device-binding!!

# ── MFA ──
MFA_ENABLED=false
```

Generate secrets:

```bash
# JWT secret (64 chars)
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"

# Pepper (64 chars)
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"

# OTP HMAC secret (32 bytes min)
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"

# Fingerprint salt (32 bytes)
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
```

---

## Step 2: Database Migration

```sql
CREATE TABLE users (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email           VARCHAR(255) UNIQUE,
    phone           VARCHAR(20) UNIQUE,
    password_hash   VARCHAR(255) NULL,       -- Argon2id hash
    name            VARCHAR(255) NULL,
    avatar          VARCHAR(512) NULL,
    provider        VARCHAR(50) NULL,        -- 'google', 'github', 'oidc', NULL for local
    provider_id     VARCHAR(255) NULL,       -- Provider-scoped user ID
    mfa_secret      VARCHAR(255) NULL,       -- TOTP secret (base32)
    mfa_enabled     TINYINT(1) DEFAULT 0,
    mfa_backup_codes JSON NULL,              -- 8 backup codes
    last_login_at   DATETIME NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone);
CREATE INDEX idx_users_provider ON users(provider, provider_id);
```

---

## Step 3: Composer Setup

```bash
composer require ghostauth/ghostauth
composer require symfony/cache   # For Redis/Memcached PSR-16 adapter
composer require nyholm/psr7     # For PSR-17 response factory
```

---

## Step 4: Bootstrap

```php
<?php
// config/auth.php or similar

use GhostAuth\GhostAuthConfiguration;
use GhostAuth\Manager\AuthManager;
use GhostAuth\Tokens\JwtTokenService;
use GhostAuth\Providers\PasswordProvider;
use GhostAuth\Providers\OtpProvider;
use GhostAuth\Providers\Social\GoogleProvider;
use GhostAuth\Providers\OidcProvider;
use GhostAuth\Security\SessionGuard;
use GhostAuth\Security\DeviceFingerprint;
use GhostAuth\Middleware\GhostAuthMiddleware;
use Symfony\Component\Cache\Adapter\RedisAdapter;
use Symfony\Component\Cache\Psr16Cache;
use Nyholm\Psr7\Factory\Psr17Factory;

// ── Redis cache (PSR-16) ──────────────────────────────────────
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$cache = new Psr16Cache(new RedisAdapter($redis));

// ── Configuration (immutable readonly class) ──────────────────
$config = GhostAuthConfiguration::fromArray([
    'app_name'          => $_ENV['APP_NAME'],
    'jwt_secret'        => $_ENV['JWT_SECRET'],
    'jwt_algorithm'     => $_ENV['JWT_ALGO'] ?? 'HS256',
    'jwt_issuer'        => $_ENV['APP_URL'],
    'jwt_audience'      => $_ENV['API_URL'],
    'jwt_ttl'           => (int) ($_ENV['JWT_TTL'] ?? 3600),
    'jwt_public_key'    => file_get_contents($_ENV['JWT_PUBLIC_KEY']) ?? null,
    'pepper'            => $_ENV['PASSWORD_PEPPER'],
    'otp_hmac_secret'   => $_ENV['OTP_HMAC_SECRET'],
    'otp_ttl'           => 300,
    'auto_provision'    => true,
    'mfa_enabled'       => (bool) ($_ENV['MFA_ENABLED'] ?? false),
    'extra'             => [
        'fingerprint_salt' => $_ENV['FINGERPRINT_SALT'] ?? '',
    ],
]);

// ── User Repository (your implementation) ─────────────────────
$userRepo = new EloquentUserRepository(); // or your implementation

// ── Token Service ─────────────────────────────────────────────
$tokenService = new JwtTokenService($config, denylistCache: $cache);

// ── Session Guard (cookie encryption + IP destroyer) ──────────
$sessionGuard = new SessionGuard(
    config:                $config,
    tokenService:          $tokenService,
    cache:                 $cache,
    maxSessionsPerUser:    (int) ($_ENV['SESSION_MAX_PER_USER'] ?? 5),
    strictIpBinding:       (bool) ($_ENV['SESSION_STRICT_IP'] ?? true),
);

// ── Auth Manager ──────────────────────────────────────────────
$auth = new AuthManager($config, $tokenService);

$auth
    ->register(new PasswordProvider($config, $userRepo, $tokenService), setDefault: true)
    ->register(new OtpProvider($config, $userRepo, $tokenService, $mailgunSender, $cache))
    ->register(new GoogleProvider(
        clientId:       $_ENV['GOOGLE_CLIENT_ID'],
        clientSecret:   $_ENV['GOOGLE_CLIENT_SECRET'],
        redirectUri:    $_ENV['APP_URL'] . '/auth/google/callback',
        config:         $config,
        userRepository: $userRepo,
        tokenService:   $tokenService,
        stateCache:     $cache,
    ));

// ── PSR-15 Middleware ─────────────────────────────────────────
$middleware = new GhostAuthMiddleware(
    tokenService:    $tokenService,
    responseFactory: new Psr17Factory(),
    sessionGuard:    $sessionGuard,
    config:          $config,
    excludedPaths:   [
        '/auth/login',
        '/auth/otp/send',
        '/auth/otp/verify',
        '/auth/google',
        '/auth/google/callback',
        '/health',
        '/docs',
    ],
    strict: true,
);
```

---

## Step 5: Auth Routes

### Login (Email + Password)

```php
$app->post('/auth/login', function (Request $request, Response $response) use ($auth, $sessionGuard) {
    $body = json_decode($request->getBody()->getContents(), true);
    $email = $body['email'] ?? '';
    $password = $body['password'] ?? '';

    if ($email === '' || $password === '') {
        return json($response, ['error' => 'Email and password required'], 400);
    }

    $result = $auth->authenticate(['email' => $email, 'password' => $password]);

    return match ($result->status) {
        AuthStatus::Authenticated => $this->createSessionAndRespond($result, $sessionGuard, $response),
        AuthStatus::PendingMfa    => json($response, ['mfa_required' => true, 'mfa_token' => $result->token], 200),
        default                   => json($response, ['error' => $result->errorMessage], 401),
    };
});

// Helper: create encrypted session cookie after successful auth
function createSessionAndRespond(AuthResult $result, SessionGuard $guard, Response $response): Response
{
    $fp = DeviceFingerprint::fromRequest($_SERVER, $_ENV['FINGERPRINT_SALT'] ?? '');
    $cookie = $guard->createSession($result->token, $fp, $result->user->getAuthIdentifier());

    return json($response, [
        'token'   => $result->token,
        'user'    => ['id' => $result->user->getAuthIdentifier(), 'email' => $result->user->getEmail()],
        'cookie_set' => true,
    ])->withHeader('Set-Cookie', buildCookieHeader($cookie));
}
```

### OTP Send

```php
$app->post('/auth/otp/send', function (Request $request, Response $response) use ($auth) {
    $body = json_decode($request->getBody()->getContents(), true);

    $result = $auth->authenticate(['email' => $body['email'] ?? ''], 'otp');

    if ($result->isPending()) {
        return json($response, [
            'message'    => 'Verification code sent',
            'expires_in' => $result->meta['expires_in'],
        ]);
    }

    return json($response, ['error' => $result->errorMessage], 400);
});
```

### OTP Verify

```php
$app->post('/auth/otp/verify', function (Request $request, Response $response) use ($auth, $sessionGuard) {
    $body = json_decode($request->getBody()->getContents(), true);

    $result = $auth->authenticate([
        'email' => $body['email'] ?? '',
        'otp'   => $body['otp']   ?? '',
    ], 'otp');

    return match ($result->status) {
        AuthStatus::Authenticated => createSessionAndRespond($result, $sessionGuard, $response),
        AuthStatus::PendingMfa    => json($response, ['mfa_required' => true, 'mfa_token' => $result->token], 200),
        default                   => json($response, ['error' => $result->errorMessage], 401),
    };
});
```

### Logout (Cookie Destroyer)

```php
$app->post('/auth/logout', function (Request $request, Response $response) use ($sessionGuard) {
    $cookies = $request->getCookieParams();
    $cookie  = $cookies[\GhostAuth\Security\SessionGuard::COOKIE_NAME] ?? null;

    if ($cookie) {
        $sessionGuard->destroySession($cookie);
    }

    return json($response, ['logged_out' => true]);
});
```

### Destroy ALL Sessions (password change / compromise)

```php
$app->post('/auth/destroy-all-sessions', function (Request $request, Response $response) use ($sessionGuard, $auth) {
    // Verify current session first
    $claims = $request->getAttribute(\GhostAuth\Middleware\GhostAuthMiddleware::CLAIMS_ATTRIBUTE);

    $purged = $sessionGuard->destroyAllUserSessions($claims['sub']);

    return json($response, [
        'sessions_destroyed' => $purged,
        'message'            => 'All sessions destroyed. You must log in again.',
    ]);
});
```

### Manage Sessions (list active devices)

```php
$app->get('/auth/sessions', function (Request $request, Response $response) use ($sessionGuard) {
    $claims = $request->getAttribute(\GhostAuth\Middleware\GhostAuthMiddleware::CLAIMS_ATTRIBUTE);
    $sessions = $sessionGuard->listUserSessions($claims['sub']);

    return json($response, ['sessions' => $sessions]);
});
```

---

## Step 6: Applying the Middleware

### With Slim 4

```php
$app->add($middleware);

// All routes after this are protected (except excluded paths)
$app->get('/dashboard', DashboardController::class);
$app->get('/api/users', UserController::class);
$app->get('/api/users/{id}', UserDetailController::class);
$app->post('/api/users/{id}', UserUpdateController::class);
```

### With any PSR-15 dispatcher

```php
// In your request pipeline:
$pipeline = new RequestHandlerMiddleware([$middleware, /* other middleware */]);
$response = $pipeline->handle($request);
```

### Accessing authenticated user in routes

```php
$app->get('/api/me', function (Request $request, Response $response) {
    // Claims from Bearer token OR session cookie
    $claims = $request->getAttribute(\GhostAuth\Middleware\GhostAuthMiddleware::CLAIMS_ATTRIBUTE);

    // Auth mode: 'bearer' or 'cookie'
    $mode = $request->getAttribute(\GhostAuth\Middleware\GhostAuthMiddleware::MODE_ATTRIBUTE);

    return json($response, [
        'user_id' => $claims['sub'],
        'email'   => $claims['email'],
        'role'    => $claims['role'] ?? 'user',
        'auth_via' => $mode,
    ]);
});
```

---

## Security Checklist

### Cookie Protection ✅

| Protection | How it works |
|---|---|
| **Encryption** | AES-256-CTR — token contents unreadable from browser |
| **Signing** | HMAC-SHA256 — modified cookies silently rejected |
| **HttpOnly** | JavaScript cannot read the cookie |
| **Secure** | Cookie only sent over HTTPS |
| **SameSite=Strict** | Prevents CSRF — cookie not sent on cross-site requests |
| **IP Binding** | Cookie tied to originating IP — replay from different IP → destroy |
| **User-Agent Binding** | Cookie tied to browser UA — stolen cookie in different browser → reject |
| **Session Rotation** | New cookie issued on every request — prevents fixation |
| **Cookie Destroyer** | IP/device change → ALL user sessions revoked immediately |
| **Max Sessions** | Configurable limit per user — oldest evicted when exceeded |

### Password Security ✅

| Protection | How it works |
|---|---|
| **Argon2id** | Memory-hard hashing — GPU/ASIC resistant |
| **Pepper** | Server-side secret — DB dump useless without env access |
| **Transparent Rehash** | Cost params upgraded automatically on login |
| **Constant-time Verify** | `password_verify()` — no timing attacks |
| **Anti-enumeration** | Dummy verify on missing users — can't guess emails via timing |

### Token Security ✅

| Protection | How it works |
|---|---|
| **CSPRNG JTI** | Each token gets random JWT ID for revocation |
| **Denylist Cache** | Revoked tokens added to Redis denylist |
| **Auto-TTL** | Denylist entries expire with token — no cleanup needed |

### OTP Security ✅

| Protection | How it works |
|---|---|
| **HMAC Storage** | OTP stored as hash — plaintext never persisted |
| **Single-use** | Cache entry deleted on first valid verify |
| **Attempt Limit** | 5 failed attempts → OTP invalidated |
| **Time-limited** | 5-minute TTL — expired OTPs auto-removed |

---

## Troubleshooting

### "Session invalidated due to suspicious device change"

Your IP changed between requests. This is normal when:
- Switching from WiFi to mobile data
- Using a VPN or Tor
- ISP changes your dynamic IP

**Fix:** Set `SESSION_STRICT_IP=false` in `.env` to disable IP binding (less secure), or keep strict mode and re-authenticate after IP changes.

### "Session cookie integrity check failed"

The cookie was tampered with or the HMAC key changed.

**Fix:** Clear browser cookies. Check that `JWT_SECRET` hasn't changed since the session was created.

### "Session has expired"

The underlying JWT expired. Session cookies cannot outlive the JWT they wrap.

**Fix:** Implement token refresh logic or increase `JWT_TTL`.

### "Headers already sent — cannot set cookie"

Output was sent before `setcookie()` was called.

**Fix:** Ensure no `echo`, `var_dump`, or whitespace before your PHP opening tag. Use output buffering if needed.

### "CookieGuard encryption key must be at least 32 bytes"

Your `JWT_SECRET` or encryption key is too short.

**Fix:** Generate a 64-character key: `php -r "echo bin2hex(random_bytes(32));"`

---

## Version Compatibility

| Feature | v1 | v2 |
|---|---|---|
| Cookie encryption | ✅ `CookieGuard` | ✅ `SessionGuard` |
| IP change destroyer | ✅ IP only | ✅ Full device fingerprint |
| Device fingerprinting | ❌ | ✅ IP + UA + Lang + salt |
| Session rotation | ❌ | ✅ Every request |
| Concurrent sessions | ❌ | ✅ Configurable limit |
| Bearer + Cookie modes | ❌ | ✅ Dual-mode middleware |
| Typed constants | ❌ | ✅ PHP 8.3 |
| Readonly config | ❌ | ✅ |
| PSR-15 middleware | ❌ | ✅ |

**Recommendation:** Use v2 for new projects. v1 `CookieGuard` is available for legacy PHP 8.2 projects that can't upgrade.

---

## New: Device Fingerprint

Detect session hijacking by binding sessions to the user's device characteristics.

```php
use GhostAuth\Security\DeviceFingerprint;

// Create fingerprint from current request
$fp = DeviceFingerprint::fromRequest($_SERVER, $_ENV['FINGERPRINT_SALT']);

// Compare against stored fingerprint
if (! $fp->matches($storedFingerprint)) {
    // Device changed! Destroy session.
    $sessionGuard->destroyUserSessions($userId, $currentToken);
}
```

---

## New: Google Authenticator (TOTP MFA)

Two-factor authentication using Google Authenticator / Authy.

### Enroll

```php
use GhostAuth\Mfa\TotpMfaHandler;

$mfa = new TotpMfaHandler(
    cache:          $cache,
    tokenService:   $tokenService,
    userRepo:       $userRepo,
    getSecret:      fn($id) => $db->getMfaSecret($id),
    saveSecret:     fn($id, $s) => $db->setMfaSecret($id, $s),
    getBackupCodes: fn($id) => $db->getBackupCodes($id),
    saveBackupCodes:fn($id, $c) => $db->setBackupCodes($id, $c),
);

// Generate enrollment data
$enrollment = $mfa->enroll($user->id, $user->email, 'MyApp');
// Returns: ['secret' => 'JBSWY3D...', 'backup_codes' => ['a1b2c3d4', ...], 'provisioning_uri' => 'otpauth://totp/...']
```

### Display QR Code

```html
<img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=<?= urlencode($enrollment['provisioning_uri']) ?>">
<p>Backup codes: <?= implode(', ', $enrollment['backup_codes']) ?></p>
```

### Verify during login

```php
// After primary auth returns pendingMfa:
$result = $mfa->handle($mfaToken, ['totp_code' => $_POST['code']]);

if ($result->isAuthenticated()) {
    // Full login complete
}
```

### Backup code recovery

```php
$result = $mfa->handle($mfaToken, ['backup_code' => $_POST['backup_code']]);
// Backup code is automatically consumed (single-use)
```

---

## New: Passkeys (WebAuthn)

Passwordless authentication using device biometrics (Face ID, Touch ID, Windows Hello).

### Register a Passkey

```php
use GhostAuth\Mfa\WebAuthnMfaHandler;

$webauthn = new WebAuthnMfaHandler(
    cache:           $cache,
    tokenService:    $tokenService,
    userRepo:        $userRepo,
    rpId:            'myapp.com',
    rpName:          'MyApp',
    origin:          'https://myapp.com',
    getCredential:   fn($id) => $db->getCredential($id),
    saveCredential:  fn($uid, $cid, $pk, $alg, $ctr) => $db->saveCredential($uid, $cid, $pk, $alg, $ctr),
);

// Step 1: Generate challenge (server)
$challenge = $webauthn->createRegistrationChallenge($user->id, $user->email, $user->name);
// Send $challenge to browser
```

**Browser (JavaScript):**

```js
// Step 2: Create credential
const credential = await navigator.credentials.create({
    publicKey: {
        challenge: Uint8Array.from(atob(challenge.challenge), c => c.charCodeAt(0)),
        rp: { id: challenge.rp_id, name: challenge.rp_name },
        user: {
            id: Uint8Array.from(atob(challenge.user_id), c => c.charCodeAt(0)),
            name: challenge.user_name,
            displayName: challenge.user_display_name,
        },
        pubKeyCredParams: challenge.algorithms,
        timeout: challenge.timeout,
    }
});
// Send credential response back to server
```

```php
// Step 3: Verify and store (server)
$result = $webauthn->completeRegistration(
    $userId,
    $challenge['challenge'],
    $clientDataJson,    // Decoded from browser
    $attestationObject, // Decoded from browser
);
// $result['credential_id'] is stored in DB
```

### Authenticate with Passkey

```php
// Step 1: Get allowed credential IDs for this user
$credIds = $db->getCredentialIds($userId);

// Step 2: Generate challenge
$authChallenge = $webauthn->createAuthenticationChallenge(allowedCredentialIds: $credIds);
// Send $authChallenge to browser (includes $authChallenge['token'])
```

**Browser (JavaScript):**

```js
const assertion = await navigator.credentials.get({
    publicKey: {
        challenge: Uint8Array.from(atob(authChallenge.challenge), c => c.charCodeAt(0)),
        allowCredentials: authChallenge.allow_credentials.map(c => ({
            type: c.type,
            id: Uint8Array.from(atob(c.id), c => c.charCodeAt(0)),
        })),
        rpId: authChallenge.rp_id,
        timeout: authChallenge.timeout,
    }
});
// Send assertion + token back to server
```

```php
// Step 3: Verify assertion (server)
$result = $webauthn->handle($authChallenge['token'], [
    'credential_id'      => $assertionId,
    'client_data'        => $clientDataJson,
    'authenticator_data' => $authenticatorData,
    'signature'          => $signature,
]);

if ($result->isAuthenticated()) {
    // Passkey auth complete — $result->token is the session JWT
}
```

---

## MFA Feature Matrix

| Feature | V1 | V2 |
|---|---|---|
| TOTP (Google Authenticator) | ✅ `TotpAuthenticator` | ✅ `TotpAuthenticator` (readonly) |
| Backup codes (8 per user) | ✅ Argon2id hashed | ✅ Argon2id hashed, auto-consumed |
| TOTP MFA Handler | ✅ `TotpMfaHandler` | ✅ `TotpMfaHandler` + `MfaHandlerInterface` |
| WebAuthn/Passkeys | ✅ `WebAuthnAuthenticator` | ✅ `WebAuthnAuthenticator` + `WebAuthnMfaHandler` |
| ES256 (ECDSA P-256) | ✅ | ✅ |
| EdDSA (Ed25519) | ✅ | ✅ |
| CBOR decoder (minimal) | ✅ | ✅ |
| Resident credentials | ✅ | ✅ |
| Signature counter | ✅ | ✅ |
| Multi-passkey per user | ❌ (manual) | ✅ `WebAuthnMfaHandler` |
| MFA Decorator | ❌ | ✅ `MfaDecorator` |
| Device Fingerprint | ✅ | ✅ IP + UA + Lang + salt |

---

## Security Notes for New Features

### TOTP
- **Secrets stored as base32 strings** — encrypt at rest in production
- **Backup codes hashed with Argon2id** — same security as passwords
- **Leeway of 1 time step** (±30s) — accounts for clock skew
- **Codes are single-use** — backup codes removed after first successful use

### Passkeys/WebAuthn
- **No shared secrets** — credentials generated by the device, server only stores public keys
- **Phishing-resistant** — origin-bound by design; can't be replayed on different domains
- **Signature counter** — incremented on each use; if it goes backward, the authenticator was cloned
- **User presence required** — biometric/PIN verification enforced by the platform authenticator
- **Ed25519 support** — faster and more secure than ECDSA; requires libsodium (PHP 8.2+)

### Device Fingerprint
- **Fingerprint salt required** — without it, fingerprints can be predicted
- **IP changes break sessions** — this is intentional (security > convenience)
- **User-Agent can change** — browser updates will trigger re-auth
- **Mobile devices** — switching WiFi/mobile data changes IP → triggers re-auth

---

## Missing Features Analysis → Now Implemented

| # | Feature | File(s) |
|---|---|---|
| 1 | Device login notifications | `Events/SecurityEvent`, `Events/EventDispatcher` |
| 2 | Trusted device system | `Security/TrustedDeviceManager` |
| 3 | Account lockout (brute force) | `Security/AccountLockout` |
| 4 | Password strength validation | `Security/PasswordStrength` |
| 5 | Password breach checking (HIBP) | `Security/PasswordBreachChecker` |
| 6 | Email verification | `Security/EmailVerification` |
| 7 | Password reset | `Security/PasswordReset` |
| 8 | Magic link authentication | `Security/MagicLink`, `Providers/MagicLinkProvider` |
| 9 | IP allowlist/denylist | `Security/IpGuard` |
| 10 | Anomaly detection | `Security/AnomalyDetector` |
| 11 | Audit events (23 types) | `Events/SecurityEvent` |
| 12 | Webhook notifications | `Events/WebhookDispatcher` |

### Quick Examples

**Notifications:** `$dispatcher->listen(SecurityEvent::DEVICE_NEW, fn($e) => sendEmail($e->userId, 'New login from '.$e->metadata['country']));`

**Trusted devices:** `$devices->isTrusted($userId, $fp->compute()) → skip MFA`

**Account lockout:** `$lockout->recordFailure($email) → auto-locks after 5 failures with exponential backoff`

**Password strength:** `PasswordStrength::analyze($pw) → score 0-4 + feedback`

**HIBP breach check:** `PasswordBreachChecker::check($pw) → k-anonymity API (only 5 hash chars sent)`

**Magic links:** `$provider->authenticate(['email' => 'user@x.com']) → email with link → click → auth`

**Anomaly detection:** `$detector->analyze($userId, $ip, $hour) → risk_score 0-100`

**Webhooks:** `$webhooks->registerWebhook($url, $secret) → HMAC-signed POST on every security event`
