<?php

declare(strict_types=1);

/**
 * GhostAuth v2 — Bootstrap & Implementation Example
 * =============================================================================
 * Demonstrates PHP 8.3 idioms throughout.
 *
 * Sections:
 *   1. Stub implementations (User, UserRepository, OtpTransport, Cache)
 *   2. GhostAuthConfiguration (readonly class, typed constants)
 *   3. JwtTokenService setup
 *   4. AuthManager wiring (PasswordProvider + OtpProvider + MfaDecorator)
 *   5. Email + Password authentication
 *   6. OTP — Phase 1: dispatch code
 *   7. OTP — Phase 2: verify code
 *   8. Token verification
 *   9. AuthManager::inspect() introspection
 * =============================================================================
 */

require_once __DIR__ . '/../vendor/autoload.php';

use GhostAuth\Contracts\AuthenticatableInterface;
use GhostAuth\Contracts\MfaHandlerInterface;
use GhostAuth\Contracts\OtpTransportInterface;
use GhostAuth\Contracts\UserRepositoryInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Enums\AuthStatus;
use GhostAuth\GhostAuthConfiguration;
use GhostAuth\Manager\AuthManager;
use GhostAuth\Providers\OtpProvider;
use GhostAuth\Providers\PasswordProvider;
use GhostAuth\Tokens\JwtTokenService;
use Psr\SimpleCache\CacheInterface;

// =============================================================================
// ANSI helpers for readable demo output
// =============================================================================
function ok(string $msg): void  { echo "\033[32m✅ {$msg}\033[0m\n"; }
function err(string $msg): void { echo "\033[31m❌ {$msg}\033[0m\n"; }
function inf(string $msg): void { echo "\033[36mℹ  {$msg}\033[0m\n"; }
function hdr(string $msg): void { echo "\n\033[1;33m═══ {$msg} ═══\033[0m\n"; }

// =============================================================================
// 1. STUB: User entity
// =============================================================================

/**
 * PHP 8.3: `readonly class` for the User entity DTO.
 * Constructor-promoted readonly properties — zero boilerplate.
 */
final class AppUser implements AuthenticatableInterface
{
    public function __construct(
        private readonly int     $id,
        private readonly string  $email,
        private readonly ?string $passwordHash = null,
        private readonly bool    $mfaEnabled   = false,
        private readonly string  $role         = 'user',
    ) {}

    public function getAuthIdentifier(): int|string { return $this->id; }
    public function getAuthIdentifierName(): string { return 'id'; }
    public function getAuthPassword(): ?string      { return $this->passwordHash; }
    public function getEmail(): ?string             { return $this->email; }
    public function getPhone(): ?string             { return null; }
    public function hasMfaEnabled(): bool           { return $this->mfaEnabled; }

    /** Extra claims embedded in every JWT issued for this user. */
    public function getJwtClaims(): array
    {
        return ['role' => $this->role, 'app_version' => '2.0'];
    }

    /** Expose password hash so the demo repository can update it. */
    public function withPassword(string $hash): self
    {
        return new self($this->id, $this->email, $hash, $this->mfaEnabled, $this->role);
    }
}

// =============================================================================
// 2. STUB: In-memory UserRepository
// =============================================================================

final class DemoUserRepository implements UserRepositoryInterface
{
    /** @var array<int, AppUser> */
    private array $store  = [];
    private int   $nextId = 1;

    public function seed(AppUser $user): void
    {
        $this->store[$user->getAuthIdentifier()] = $user;
    }

    public function findByEmail(string $email): ?AuthenticatableInterface
    {
        foreach ($this->store as $u) {
            if (strtolower((string) $u->getEmail()) === strtolower($email)) {
                return $u;
            }
        }
        return null;
    }

    public function findByPhone(string $phone): ?AuthenticatableInterface
    {
        return null;
    }

    public function findById(int|string $id): ?AuthenticatableInterface
    {
        return $this->store[$id] ?? null;
    }

    public function create(array $attributes): AuthenticatableInterface
    {
        $user = new AppUser(
            id:    $this->nextId++,
            email: (string) ($attributes['email'] ?? ''),
        );
        $this->store[$user->getAuthIdentifier()] = $user;
        return $user;
    }

    public function update(int|string $id, array $attributes): bool
    {
        if (! isset($this->store[$id])) {
            return false;
        }
        // Handle transparent password rehash
        if (isset($attributes['password'])) {
            $this->store[$id] = $this->store[$id]->withPassword($attributes['password']);
        }
        return true;
    }
}

// =============================================================================
// 3. STUB: Console OTP transport (prints to stdout)
// =============================================================================

final class ConsoleOtpTransport implements OtpTransportInterface
{
    /** Captures the last sent OTP for demo verification in Phase 2. */
    public ?string $lastOtp = null;

    public function dispatch(string $recipient, string $otp, string $channel): bool
    {
        $this->lastOtp = $otp;
        inf("[{$channel}] → {$recipient}: OTP = \033[1;35m{$otp}\033[0;36m");
        return true;
    }
}

// =============================================================================
// 4. STUB: In-process PSR-16 array cache
// =============================================================================

final class ArrayCache implements CacheInterface
{
    private array $store  = [];
    private array $expiry = [];

    public function get(string $key, mixed $default = null): mixed
    {
        if (isset($this->expiry[$key]) && $this->expiry[$key] < time()) {
            $this->delete($key);
            return $default;
        }
        return $this->store[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->store[$key] = $value;
        if (is_int($ttl)) {
            $this->expiry[$key] = time() + $ttl;
        }
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key], $this->expiry[$key]);
        return true;
    }

    public function clear(): bool { $this->store = []; $this->expiry = []; return true; }
    public function has(string $key): bool { return $this->get($key) !== null; }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $k) {
            yield $k => $this->get($k, $default);
        }
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $k => $v) {
            $this->set($k, $v, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $k) {
            $this->delete($k);
        }
        return true;
    }
}

// =============================================================================
// 5. WIRE UP GHOSTAUTH
// =============================================================================

hdr('GhostAuth v2 — PHP 8.3 Bootstrap');

// ── GhostAuthConfiguration (readonly class) ──────────────────────────────────
// PHP 8.3: GhostAuthConfiguration::fromArray uses typed constants for defaults.
$config = GhostAuthConfiguration::fromArray([
    'app_name'        => 'DemoApp',
    'jwt_secret'      => 'demo-hs256-secret-min-32-bytes-ok!!',  // ← env var in prod
    'jwt_issuer'      => 'https://demo.example.com',
    'jwt_audience'    => 'https://api.demo.example.com',
    'jwt_ttl'         => 3600,
    'otp_hmac_secret' => bin2hex('ghostauth-otp-hmac-secret!!'), // ← env var in prod
    'otp_length'      => 6,
    'otp_ttl'         => 300,
    'auto_provision'  => true,
    'mfa_enabled'     => false,
]);

inf('Config: ' . $config->appName . ' | algo: ' . $config->hashAlgorithm->label());
inf('JWT TTL: ' . $config->jwtTtlSeconds . 's | Token driver: ' . $config->tokenDriver->value);

// ── Infrastructure ────────────────────────────────────────────────────────────
$cache      = new ArrayCache();
$users      = new DemoUserRepository();
$transport  = new ConsoleOtpTransport();
$tokenSvc   = new JwtTokenService($config, denylistCache: $cache);

// ── Providers ─────────────────────────────────────────────────────────────────
$passwordProvider = new PasswordProvider(
    config:         $config,
    userRepository: $users,
    tokenService:   $tokenSvc,
);

$otpProvider = new OtpProvider(
    config:         $config,
    userRepository: $users,
    tokenService:   $tokenSvc,
    transport:      $transport,
    cache:          $cache,
);

// ── Seed a user with a hashed password ───────────────────────────────────────
$alice = new AppUser(id: 1, email: 'alice@example.com');
// Re-construct with the hashed password using PasswordProvider::hash()
$alice = $alice->withPassword($passwordProvider->hash('correct-horse-staple'));
$users->seed($alice);

// ── AuthManager ───────────────────────────────────────────────────────────────
$auth = new AuthManager($config, $tokenSvc);
$auth
    ->register($passwordProvider, setDefault: true)  // 'password' is now the default
    ->register($otpProvider);

// =============================================================================
// 6. EMAIL + PASSWORD AUTHENTICATION
// =============================================================================

hdr('Email + Password');

$result = $auth->authenticate(
    credentials: ['email' => 'alice@example.com', 'password' => 'correct-horse-staple'],
    // provider: 'password' is omitted — uses default
);

// PHP 8.3: match on backed enum for exhaustive, type-safe handling
$_ = match ($result->status) {
    AuthStatus::Authenticated => (function () use ($result): void {
        ok("Logged in as user #{$result->user?->getAuthIdentifier()} (latency: {$result->latencyMs}ms)");
        ok('JWT (first 40 chars): ' . substr((string) $result->token, 0, 40) . '...');
    })(),
    AuthStatus::PendingMfa => (function () use ($result): void {
        inf("MFA required for user #{$result->user?->getAuthIdentifier()}");
    })(),
    default => (function () use ($result): void {
        err("Login failed: [{$result->errorCode}] {$result->errorMessage}");
    })(),
};

$validToken = $result->token; // Save for token verification demo

// ── Wrong password (expect INVALID_CREDENTIALS) ───────────────────────────────
$bad = $auth->authenticate(['email' => 'alice@example.com', 'password' => 'hunter2']);

$bad->isFailed()
    ? err("Correctly rejected: [{$bad->errorCode}] {$bad->errorMessage}")
    : ok('Unexpected success — this should not happen');

// =============================================================================
// 7. OTP — PHASE 1: DISPATCH CODE
// =============================================================================

hdr('Passwordless OTP — Phase 1: Send');

$sendResult = $auth->authenticate(
    credentials: ['email' => 'bob@example.com'],  // bob doesn't exist yet → auto-provision
    provider:    'otp',
);

// PHP 8.3: inspect status using the enum's built-in helpers
if ($sendResult->isPending()) {
    ok("Code dispatched! Channel: {$sendResult->meta['channel']} | Expires in: {$sendResult->meta['expires_in']}s");
}

// =============================================================================
// 8. OTP — PHASE 2: VERIFY CODE
// =============================================================================

hdr('Passwordless OTP — Phase 2: Verify');

// The ConsoleOtpTransport captured the plaintext OTP for us
$capturedOtp = $transport->lastOtp;
inf("Captured OTP from transport: \033[1;35m{$capturedOtp}\033[0;36m");

$verifyResult = $auth->authenticate(
    credentials: ['email' => 'bob@example.com', 'otp' => $capturedOtp],
    provider:    'otp',
);

match ($verifyResult->status) {
    AuthStatus::Authenticated => ok("OTP verified! User #{$verifyResult->user?->getAuthIdentifier()} authenticated in {$verifyResult->latencyMs}ms"),
    default                   => err("[{$verifyResult->errorCode}] {$verifyResult->errorMessage}"),
};

// ── Wrong OTP attempt ─────────────────────────────────────────────────────────
// First, send a new OTP for alice to demonstrate the invalid-OTP path
$auth->authenticate(['email' => 'alice@example.com'], 'otp');

$wrongAttempt = $auth->authenticate(
    credentials: ['email' => 'alice@example.com', 'otp' => '000000'],
    provider:    'otp',
);

$wrongAttempt->isFailed()
    ? err("Correctly rejected: [{$wrongAttempt->errorCode}] — attempts remaining: {$wrongAttempt->meta['attempts_remaining']}")
    : ok('Unexpected success — this should not happen');

// =============================================================================
// 9. TOKEN VERIFICATION
// =============================================================================

hdr('Token Verification + Logout');

if ($validToken !== null) {
    try {
        $payload = $auth->verifyToken($validToken);
        ok("Token valid: sub={$payload['sub']}, exp={$payload['exp']}, role={$payload['role']}");
    } catch (\GhostAuth\Exceptions\TokenException $e) {
        err("Token invalid: {$e->getMessage()}");
    }

    $revoked = $auth->revokeToken($validToken);
    $revoked
        ? ok('Token revoked (added to denylist cache).')
        : inf('Revocation is a no-op — configure denylistCache to enable.');
}

// =============================================================================
// 10. AUTHMANAGER INTROSPECTION (PHP 8.3 json_encode for pretty debug output)
// =============================================================================

hdr('AuthManager Introspection');

$info = $auth->inspect();
echo json_encode($info, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";

echo "\n\033[1;32m✨  GhostAuth v2 demo complete.\033[0m\n\n";
