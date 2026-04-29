# SKILLS.md — GhostAuth v2

> Quick-reference skill cards for common development tasks. All code uses PHP 8.3 idioms.

---

## 🔐 Skill: Add a New Authentication Strategy

**When:** You need a custom method (magic link, SAML, passkey, API key, etc.)

```php
use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\DTO\AuthResult;

final class MagicLinkStrategy implements AuthenticationStrategy
{
    public const string CACHE_PREFIX = 'ghostauth:magic:token:';
    public const int    TOKEN_TTL    = 900; // 15 minutes

    public function authenticate(array $credentials): AuthResult
    {
        // Phase 1 (no 'token'): generate + send magic link
        // Phase 2 ('token' present): verify + issue JWT
        return match (true) {
            ! isset($credentials['token']) => $this->send((string) $credentials['email']),
            default                         => $this->verify((string) $credentials['email'], (string) $credentials['token']),
        };
    }

    public function name(): string        { return 'magic_link'; }
    public function isAvailable(): bool   { return $this->enabled; }

    private function send(string $email): AuthResult      { /* ... */ }
    private function verify(string $email, string $token): AuthResult { /* ... */ }
}

// Register:
$auth->register(new MagicLinkStrategy(...));
$auth->authenticate(['email' => 'alice@example.com'], 'magic_link');
```

---

## 🌐 Skill: Add a New Social Provider

**When:** You need Facebook, LinkedIn, Apple, Discord, etc.

```php
use GhostAuth\DTO\SocialProfile;
use GhostAuth\Providers\AbstractOAuthProvider;

final class DiscordProvider extends AbstractOAuthProvider
{
    public const string AUTHORIZATION_ENDPOINT = 'https://discord.com/oauth2/authorize';
    public const string TOKEN_ENDPOINT         = 'https://discord.com/api/oauth2/token';
    public const string USERINFO_ENDPOINT      = 'https://discord.com/api/users/@me';

    public function name(): string { return 'discord'; }

    protected function authorizationEndpoint(): string { return self::AUTHORIZATION_ENDPOINT; }
    protected function tokenEndpoint(): string         { return self::TOKEN_ENDPOINT; }
    protected function userInfoEndpoint(): string      { return self::USERINFO_ENDPOINT; }
    protected function defaultScopes(): array          { return ['identify', 'email']; }

    protected function buildProfile(string $jsonBody, string $accessToken, ?string $refreshToken): SocialProfile
    {
        // json_validate() is called inside SocialProfile::fromJson() automatically
        return SocialProfile::fromJson(
            json:         $jsonBody,
            providerName: $this->name(),
            accessToken:  $accessToken,
            refreshToken: $refreshToken,
            mapper: static fn(array $raw) => [
                'id'     => (string) ($raw['id'] ?? ''),
                'name'   => $raw['username'] ?? null,
                'email'  => $raw['email']    ?? null,
                'avatar' => isset($raw['id'], $raw['avatar'])
                    ? "https://cdn.discordapp.com/avatars/{$raw['id']}/{$raw['avatar']}.png"
                    : null,
            ],
        );
    }
}
```

---

## 🔒 Skill: Implement MFA with TOTP

**When:** You want Google Authenticator / Authy support.

```php
use GhostAuth\Contracts\MfaHandlerInterface;
use GhostAuth\Contracts\AuthenticatableInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Enums\AuthStatus;

final class TotpMfaHandler implements MfaHandlerInterface
{
    public const string BRIDGE_PREFIX = 'ghostauth:mfa:bridge:';
    public const int    BRIDGE_TTL    = 300;

    public function __construct(
        private readonly \OTPHP\TOTP         $totp,  // spomky-labs/otphp
        private readonly \Psr\SimpleCache\CacheInterface $cache,
        private readonly \GhostAuth\Contracts\TokenServiceInterface $tokenService,
    ) {}

    public function handle(string $mfaToken, array $credentials): AuthResult
    {
        // Look up the user tied to this bridge token
        $userId = $this->cache->get(self::BRIDGE_PREFIX . $mfaToken);
        if ($userId === null) {
            return AuthResult::failed('MFA_TOKEN_EXPIRED', 'MFA session expired. Please log in again.');
        }

        // Verify TOTP code
        $code = (string) ($credentials['totp_code'] ?? '');
        if (! $this->totp->verify($code, leeway: 1)) {
            return AuthResult::failed('MFA_CODE_INVALID', 'Invalid authenticator code.');
        }

        // Consume bridge token — single use
        $this->cache->delete(self::BRIDGE_PREFIX . $mfaToken);

        // Issue final token
        $user  = $this->userRepo->findById($userId);
        $token = $this->tokenService->issue($user, ['mfa' => 'totp']);

        return AuthResult::authenticated($user, $token, ['mfa_method' => 'totp']);
    }

    public function enroll(AuthenticatableInterface $user): array
    {
        $secret = random_bytes(20); // 160-bit secret
        $totp   = \OTPHP\TOTP::createFromSecret(base32_encode($secret));
        $totp->setLabel($user->getEmail());

        return [
            'secret'       => $totp->getSecret(),
            'qr_url'       => $totp->getQrCodeUri(),
            'backup_codes' => $this->generateBackupCodes(),
        ];
    }

    public function isAvailable(): bool { return true; }

    private function generateBackupCodes(): array
    {
        return array_map(
            fn() => bin2hex(random_bytes(5)), // 10-char hex backup codes
            range(1, 8)
        );
    }
}

// Wire it up:
use GhostAuth\Decorators\MfaDecorator;

$auth->register(new MfaDecorator(
    inner:      new PasswordProvider($config, $userRepo, $tokenSvc),
    mfaHandler: new TotpMfaHandler($totp, $cache, $tokenSvc),
));
```

---

## 🛡️ Skill: Use the PSR-15 Middleware

**With Slim 4:**

```php
use GhostAuth\Middleware\GhostAuthMiddleware;

$middleware = new GhostAuthMiddleware(
    tokenService:    $tokenService,
    responseFactory: new \Nyholm\Psr7\Factory\Psr17Factory(),
    excludedPaths:   ['/auth/login', '/auth/otp/send', '/auth/otp/verify', '/health'],
    strict:          true,
);

$app->add($middleware);

// In a route handler:
$app->get('/profile', function (Request $request, Response $response) {
    $claims = $request->getAttribute(GhostAuthMiddleware::CLAIMS_ATTRIBUTE);
    $userId = $claims['sub'];
    // ...
});
```

**With any PSR-15 dispatcher:**

```php
// Manual dispatch:
$response = $middleware->process($request, $handler);
```

---

## 🔧 Skill: Build Configuration from Environment

```php
use GhostAuth\GhostAuthConfiguration;

// Load from .env (e.g. via vlucas/phpdotenv)
$config = GhostAuthConfiguration::fromArray([
    'app_name'        => $_ENV['APP_NAME'],
    'jwt_secret'      => $_ENV['JWT_SECRET'],          // ≥ 32 bytes
    'jwt_algorithm'   => $_ENV['JWT_ALGO'] ?? 'HS256', // or RS256
    'jwt_issuer'      => $_ENV['APP_URL'],
    'jwt_audience'    => $_ENV['API_URL'],
    'jwt_ttl'         => (int) ($_ENV['JWT_TTL'] ?? 3600),
    'jwt_public_key'  => $_ENV['JWT_PUBLIC_KEY'] ?? null, // for RS256
    'pepper'          => $_ENV['PASSWORD_PEPPER'],
    'otp_hmac_secret' => $_ENV['OTP_HMAC_SECRET'],     // ≥ 32 bytes
    'otp_ttl'         => 300,
    'auto_provision'  => true,
    'mfa_enabled'     => (bool) ($_ENV['MFA_ENABLED'] ?? false),
]);

// $config is readonly — safe to share across all providers
```

---

## 📊 Skill: Structured Auth Logging

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('ghostauth');
$logger->pushHandler(new StreamHandler('php://stderr', Logger::INFO));

$auth = new AuthManager($config, $tokenService, logger: $logger);

// Every authenticate() call logs:
// INFO  ghostauth.AuthManager: dispatching → 'password'
// INFO  ghostauth.AuthManager: 'password' → authenticated  {user_id: 42, latency_ms: 12.4}
// WARN  ghostauth.AuthManager: 'password' → failed         {error_code: INVALID_CREDENTIALS}

// Access the log-safe result payload manually:
$result = $auth->authenticate($credentials);
$logger->info('Auth attempt', $result->toLogContext());
// ['status' => 'authenticated', 'user_id' => 42, 'latency_ms' => 12.4, 'token_preview' => 'eyJhbGci...']
```

---

## 🧪 Skill: PHPUnit Testing with v2

```php
use PHPUnit\Framework\TestCase;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Enums\AuthStatus;

class PasswordProviderTest extends TestCase
{
    public function test_authenticated_result_shape(): void
    {
        $user     = $this->createMock(AuthenticatableInterface::class);
        $user->method('getAuthIdentifier')->willReturn(42);
        $user->method('getAuthPassword')->willReturn(password_hash('secret', PASSWORD_ARGON2ID));
        $user->method('hasMfaEnabled')->willReturn(false);
        $user->method('getJwtClaims')->willReturn([]);

        $tokenSvc = $this->createMock(TokenServiceInterface::class);
        $tokenSvc->method('issue')->willReturn('jwt.signed.token');

        $userRepo = $this->createMock(UserRepositoryInterface::class);
        $userRepo->method('findByEmail')->willReturn($user);

        $provider = new PasswordProvider($this->config(), $userRepo, $tokenSvc);
        $result   = $provider->authenticate(['email' => 'a@a.com', 'password' => 'secret']);

        // Test readonly DTO properties
        $this->assertSame(AuthStatus::Authenticated, $result->status);
        $this->assertTrue($result->isAuthenticated());
        $this->assertSame('jwt.signed.token', $result->token);
        $this->assertSame(42, $result->user->getAuthIdentifier());
        $this->assertGreaterThan(0, $result->latencyMs);
    }

    public function test_failed_result_is_immutable(): void
    {
        // readonly class — any mutation attempt is a compile-time error
        $result = AuthResult::failed('TEST', 'test error');
        $this->assertSame(AuthStatus::Failed, $result->status);
        $this->assertTrue($result->isFailed());
        $this->assertNull($result->token);
        $this->assertNull($result->user);
    }

    private function config(): GhostAuthConfiguration
    {
        return GhostAuthConfiguration::fromArray([
            'app_name'        => 'Test',
            'jwt_secret'      => str_repeat('x', 32),
            'otp_hmac_secret' => str_repeat('y', 32),
        ]);
    }
}
```

---

## 🔄 Skill: Migrate from v1 to v2

| v1 | v2 | Notes |
|---|---|---|
| `GhostAuthManager` | `AuthManager` | Same concept, richer API |
| `registerProvider($p)` | `register($p)` | Shorter |
| `$result->isSuccess()` | `$result->isAuthenticated()` | More precise |
| `$result->getToken()` | `$result->token` | Readonly property |
| `$result->getUser()` | `$result->user` | Readonly property |
| `$result->getErrorCode()` | `$result->errorCode` | Readonly property |
| `AuthResultInterface` | `AuthResult` (concrete) | No interface needed |
| `getProviderName()` | `name()` | On `AuthenticationStrategy` |
| `isEnabled()` | `isAvailable()` | On `AuthenticationStrategy` |
| `EmailPasswordProvider` | `PasswordProvider` | Shorter name |
| `OtpSenderInterface::send()` | `OtpTransportInterface::dispatch()` | |
| `TokenIssuerInterface` | `TokenServiceInterface` | |
| `UserProviderInterface` | `UserRepositoryInterface` | |
| `JwtIssuer` | `JwtTokenService` | |
| `SocialUserInterface` | `SocialProfile` (DTO) | |
| `getAuthorizationUrl()` | `authorizationUrl()` | On social providers |
