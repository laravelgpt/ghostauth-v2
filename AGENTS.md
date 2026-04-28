# AGENTS.md — GhostAuth v2

> Guidance for AI coding agents (Copilot, Cursor, Kilo, Claude, etc.) working on this codebase.

---

## Project Identity

- **Package:** `ghostauth/ghostauth` (v2 branch)
- **PHP:** `^8.3` — use 8.3 features deliberately
- **Architecture:** Strategy + Decorator Pattern, PSR-4/7/11/15
- **Key difference from v1:** `readonly` everywhere, backed enums, `json_validate()`, PSR-15 middleware, MFA decorator

---

## Directory Map

```
src/
├── GhostAuthConfiguration.php        ← readonly class. Never add mutability here.
├── Contracts/                         ← Public API. Never break these.
│   ├── AuthenticationStrategy.php    ← Core strategy interface. PROVIDER_* typed constants.
│   ├── AuthenticatableInterface.php  ← hasMfaEnabled() is required — v2 addition.
│   ├── UserRepositoryInterface.php
│   ├── TokenServiceInterface.php
│   ├── OtpTransportInterface.php
│   └── MfaHandlerInterface.php       ← New in v2. Implement for TOTP, backup codes, etc.
├── DTO/                               ← All readonly classes. No setters, no mutation.
│   ├── AuthResult.php                ← Use static factories. Never `new AuthResult(...)` directly.
│   ├── OtpPayload.php
│   └── SocialProfile.php             ← fromJson() uses json_validate() — always use this factory.
├── Decorators/
│   └── MfaDecorator.php              ← Wraps any AuthenticationStrategy. Transparent to AuthManager.
├── Enums/
│   ├── AuthStatus.php                ← Match on this, not on string codes.
│   ├── HashAlgorithm.php
│   └── TokenDriver.php
├── Exceptions/                        ← 6 files. Same rule: throw only on infra errors.
├── Manager/
│   └── AuthManager.php               ← Central engine. register() + authenticate() + inspect().
├── Middleware/
│   └── GhostAuthMiddleware.php       ← PSR-15. CLAIMS_ATTRIBUTE / TOKEN_ATTRIBUTE constants.
├── Providers/
│   ├── PasswordProvider.php
│   ├── OtpProvider.php
│   ├── AbstractOAuthProvider.php     ← Extend this for new social providers.
│   ├── OidcProvider.php
│   └── Social/
│       ├── GoogleProvider.php
│       └── GitHubProvider.php
└── Tokens/
    └── JwtTokenService.php
```

---

## PHP 8.3 Rules (Enforced)

### Use `readonly class` for all DTOs and config
```php
// ✅ New DTO
readonly class TokenMetadata
{
    public function __construct(
        public readonly string $jti,
        public readonly int    $issuedAt,
        public readonly int    $expiresAt,
    ) {}
}

// ❌ Mutable DTO
class TokenMetadata
{
    public string $jti;
    public function setJti(string $jti): void { $this->jti = $jti; }
}
```

### Use typed class constants
```php
// ✅
public const string CACHE_PREFIX = 'ghostauth:myfeature:';
public const int    TTL          = 300;

// ❌ (PHP < 8.3 style)
public const CACHE_PREFIX = 'ghostauth:myfeature:';
```

### Use `json_validate()` before `json_decode()` on external data
```php
// ✅
if (! json_validate($body)) {
    throw new SocialAuthException('Invalid JSON from provider.');
}
$data = json_decode($body, associative: true);

// ❌
$data = json_decode($body, true);
if ($data === null) { ... }
```

### Use backed enums for all state/type discriminators
```php
// ✅ New status enum
enum NotificationChannel: string
{
    case Email    = 'email';
    case Sms      = 'sms';
    case WhatsApp = 'whatsapp';
}

// ❌ String constants
const CHANNEL_EMAIL = 'email';
```

### Use `match` over `if/elseif` chains
```php
// ✅
$action = match ($result->status) {
    AuthStatus::Authenticated => $this->issueSession($result->user),
    AuthStatus::PendingMfa    => $this->redirectToMfa($result->token),
    AuthStatus::Failed        => $this->rejectRequest($result->errorMessage),
    default                   => throw new \LogicException('Unhandled status'),
};

// ❌
if ($result->isSuccess()) { ... }
elseif ($result->getErrorCode() === 'MFA_REQUIRED') { ... }
```

---

## Core Conventions (Same as v1, restated for v2 context)

### 1. Auth failures → `AuthResult::failed()`, never throw
### 2. CSPRNG everywhere — `random_bytes()` / `random_int()`
### 3. Never store OTP plaintext — HMAC-SHA256 only
### 4. `hash_equals()` for constant-time comparison
### 5. Generic credential error messages

---

## Adding a New Social Provider (v2 pattern)

1. Extend `AbstractOAuthProvider`
2. Implement 5 abstract methods
3. Use `SocialProfile::fromJson()` with a `$mapper` callable in `buildProfile()`

```php
final class FacebookProvider extends AbstractOAuthProvider
{
    public const string AUTHORIZATION_ENDPOINT = 'https://www.facebook.com/v18.0/dialog/oauth';
    public const string TOKEN_ENDPOINT         = 'https://graph.facebook.com/v18.0/oauth/access_token';
    public const string USERINFO_ENDPOINT      = 'https://graph.facebook.com/me?fields=id,name,email,picture';

    public function name(): string { return AuthenticationStrategy::PROVIDER_FACEBOOK; }

    protected function authorizationEndpoint(): string { return self::AUTHORIZATION_ENDPOINT; }
    protected function tokenEndpoint(): string         { return self::TOKEN_ENDPOINT; }
    protected function userInfoEndpoint(): string      { return self::USERINFO_ENDPOINT; }
    protected function defaultScopes(): array          { return ['email', 'public_profile']; }

    protected function buildProfile(string $jsonBody, string $accessToken, ?string $refreshToken): SocialProfile
    {
        return SocialProfile::fromJson(
            json:         $jsonBody,
            providerName: $this->name(),
            accessToken:  $accessToken,
            refreshToken: $refreshToken,
            mapper: static fn(array $raw) => [
                'id'     => (string) ($raw['id'] ?? ''),
                'name'   => $raw['name']  ?? null,
                'email'  => $raw['email'] ?? null,
                'avatar' => $raw['picture']['data']['url'] ?? null,
            ],
        );
    }
}
```

---

## Adding MFA Support

1. Implement `MfaHandlerInterface`
2. Wrap target strategy with `MfaDecorator`
3. Register as usual

```php
class TotpMfaHandler implements MfaHandlerInterface
{
    public function handle(string $mfaToken, array $credentials): AuthResult { ... }
    public function enroll(AuthenticatableInterface $user): array            { ... }
    public function isAvailable(): bool                                      { return true; }
}

$auth->register(new MfaDecorator(
    new PasswordProvider($config, $userRepo, $tokenSvc),
    new TotpMfaHandler($totpLibrary, $cache),
));
```

---

## What NOT to Do

- ❌ Do not add mutable state to DTO classes — use `readonly`
- ❌ Do not `json_decode()` external data without `json_validate()` first
- ❌ Do not use string comparisons (`===`) for OTPs or tokens — use `hash_equals()`
- ❌ Do not add framework code
- ❌ Do not use `rand()`, `uniqid()`, `microtime()` for cryptographic values
- ❌ Do not break `AuthenticationStrategy` interface without major version bump
- ❌ Do not use `if/else` chains where `match` is cleaner
- ❌ Do not skip `isAvailable()` check before dispatching — `AuthManager` does this, don't bypass it

---

## Middleware Usage Notes

The `GhostAuthMiddleware` attaches verified claims to the request:

```php
// In any downstream handler:
$claims = $request->getAttribute(GhostAuthMiddleware::CLAIMS_ATTRIBUTE);
// ['sub' => '42', 'email' => 'alice@...', 'role' => 'admin', ...]

$token = $request->getAttribute(GhostAuthMiddleware::TOKEN_ATTRIBUTE);
// Raw JWT string (for revocation on logout)
```

Excluded paths bypass auth entirely — always include your login/OTP endpoints:

```php
new GhostAuthMiddleware(
    excludedPaths: ['/auth/login', '/auth/otp/send', '/auth/otp/verify', '/health', '/docs'],
);
```
