<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\Contracts\OtpTransportInterface;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Contracts\UserRepositoryInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\DTO\OtpPayload;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\GhostAuthConfiguration;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * OtpProvider
 *
 * Passwordless authentication via One-Time Passwords over Email or SMS.
 * Implements a two-phase flow via a single `authenticate()` entry point:
 *
 *   Phase 1 — DISPATCH (no 'otp' key in $credentials):
 *     Input:  ['email' => '...'] | ['phone' => '...']
 *     Output: AuthResult::pendingOtp() — OTP sent, awaiting verification.
 *
 *   Phase 2 — VERIFY ('otp' key present):
 *     Input:  ['email' => '...', 'otp' => '123456']
 *     Output: AuthResult::authenticated() — full token issued.
 *
 * PHP 8.3 features:
 *   - Typed class constants (`public const string`).
 *   - `readonly` promoted constructor parameters.
 *   - `OtpPayload` readonly DTO for type-safe OTP data.
 *   - `json_validate()` via SocialProfile (see DTO layer).
 *   - `match` expressions for channel dispatch.
 *   - DNF types where applicable in private helpers.
 *
 * Security model:
 *   - CSPRNG generation via `random_int()`.
 *   - NEVER store plaintext OTP — store HMAC-SHA256 digest only.
 *   - Single-use: cache entry deleted immediately on first valid verify.
 *   - Attempt limiting: brute-force protection on the small OTP keyspace.
 *   - Constant-time comparison via `hash_equals()`.
 *
 * @package GhostAuth\Providers
 */
final class OtpProvider implements AuthenticationStrategy
{
    // -------------------------------------------------------------------------
    // PHP 8.3: Typed class constants
    // -------------------------------------------------------------------------

    public const  CHANNEL_EMAIL   = 'email';
    public const  CHANNEL_SMS     = 'sms';

    /** PSR-16 cache key prefixes. */
    public const  CACHE_OTP      = 'ghostauth:otp:hmac:';
    public const  CACHE_ATTEMPTS = 'ghostauth:otp:attempts:';

    // -------------------------------------------------------------------------
    // Constructor (PHP 8.3: promoted readonly properties)
    // -------------------------------------------------------------------------

    public function __construct(
        private readonly GhostAuthConfiguration  $config,
        private readonly UserRepositoryInterface $userRepository,
        private readonly TokenServiceInterface   $tokenService,
        private readonly OtpTransportInterface   $transport,
        private readonly CacheInterface          $cache,
        private readonly bool                    $enabled  = true,
        private readonly LoggerInterface         $logger   = new NullLogger(),
    ) {}

    // -------------------------------------------------------------------------
    // AuthenticationStrategy
    // -------------------------------------------------------------------------

    /**
     * Route to dispatch or verify based on presence of 'otp' in $credentials.
     *
     * @param  array<string, mixed> $credentials
     * @throws GhostAuthException
     */
    public function authenticate(array $credentials): AuthResult
    {
        $this->guardAvailable();

        [$identifier, $channel] = $this->resolveIdentifier($credentials);

        return isset($credentials['otp']) && (string) $credentials['otp'] !== ''
            ? $this->verify($identifier, $channel, (string) $credentials['otp'])
            : $this->dispatch($identifier, $channel);
    }

    public function name(): string
    {
        return AuthenticationStrategy::PROVIDER_OTP;
    }

    public function isAvailable(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // Phase 1: Dispatch
    // -------------------------------------------------------------------------

    /**
     * Generate, store (as HMAC), and send an OTP.
     *
     * @throws \GhostAuth\Exceptions\OtpTransportException
     */
    private function dispatch(string $identifier, string $channel): AuthResult
    {
        $start = hrtime(as_num: true);

        // ── 1. Generate CSPRNG OTP ───────────────────────────────────────────
        $plaintext = $this->generateOtp();

        // ── 2. Compute HMAC — never store plaintext ──────────────────────────
        $hmac     = $this->hmac($plaintext);
        $cacheKey = $this->otpCacheKey($identifier);

        // ── 3. Persist HMAC with TTL ─────────────────────────────────────────
        $this->cache->set($cacheKey, $hmac, $this->config->otpTtlSeconds);

        // ── 4. Reset attempt counter ─────────────────────────────────────────
        $this->cache->delete($this->attemptCacheKey($identifier));

        // ── 5. Build the OtpPayload DTO and dispatch ─────────────────────────
        $payload = new OtpPayload(
            plaintext: $plaintext,
            hmac:      $hmac,
            recipient: $identifier,
            channel:   $channel,
            expiresAt: time() + $this->config->otpTtlSeconds,
            cacheKey:  $cacheKey,
        );

        $this->transport->dispatch($payload->recipient, $payload->plaintext, $payload->channel);

        $this->logger->info('OtpProvider: OTP dispatched', [
            'channel'    => $channel,
            'recipient'  => $this->mask($identifier),
            'expires_in' => $payload->expiresInSeconds(),
            'latency_ms' => round((hrtime(as_num: true) - $start) / 1_000_000, 2),
        ]);

        return AuthResult::pendingOtp(
            meta: [
                'channel'    => $channel,
                'expires_in' => $payload->expiresInSeconds(),
                'recipient'  => $this->mask($identifier),
            ],
            latencyMs: (hrtime(as_num: true) - $start) / 1_000_000,
        );
    }

    // -------------------------------------------------------------------------
    // Phase 2: Verify
    // -------------------------------------------------------------------------

    /**
     * Verify a submitted OTP against the stored HMAC and issue a token on success.
     */
    private function verify(string $identifier, string $channel, string $submitted): AuthResult
    {
        $start      = hrtime(as_num: true);
        $attemptKey = $this->attemptCacheKey($identifier);
        $otpKey     = $this->otpCacheKey($identifier);

        // ── 1. Check attempt count (brute-force guard) ────────────────────────
        $attempts = (int) $this->cache->get($attemptKey, default: 0);

        if ($attempts >= $this->config->otpMaxAttempts) {
            $this->cache->delete($otpKey);
            $this->cache->delete($attemptKey);

            $this->logger->warning('OtpProvider: OTP invalidated — max attempts exceeded', [
                'recipient' => $this->mask($identifier),
            ]);

            return AuthResult::failed(
                errorCode:    'OTP_MAX_ATTEMPTS',
                errorMessage: 'Too many incorrect attempts. Please request a new verification code.',
                latencyMs:    (hrtime(as_num: true) - $start) / 1_000_000,
            );
        }

        // ── 2. Retrieve stored HMAC ──────────────────────────────────────────
        $storedHmac = $this->cache->get($otpKey);

        if ($storedHmac === null) {
            return AuthResult::failed(
                errorCode:    'OTP_NOT_FOUND',
                errorMessage: 'No active verification code found. Please request a new one.',
                latencyMs:    (hrtime(as_num: true) - $start) / 1_000_000,
            );
        }

        // ── 3. Constant-time HMAC comparison ────────────────────────────────
        if (! hash_equals((string) $storedHmac, $this->hmac($submitted))) {
            $this->cache->set($attemptKey, $attempts + 1, $this->config->otpTtlSeconds);

            $this->logger->warning('OtpProvider: OTP verification failed', [
                'recipient'         => $this->mask($identifier),
                'attempt'           => $attempts + 1,
                'attempts_remaining' => $this->config->otpMaxAttempts - $attempts - 1,
            ]);

            return AuthResult::failed(
                errorCode:    'OTP_INVALID',
                errorMessage: 'The verification code you entered is incorrect.',
                meta:         ['attempts_remaining' => $this->config->otpMaxAttempts - $attempts - 1],
                latencyMs:    (hrtime(as_num: true) - $start) / 1_000_000,
            );
        }

        // ── 4. Consume OTP — single use, delete immediately ──────────────────
        $this->cache->delete($otpKey);
        $this->cache->delete($attemptKey);

        // ── 5. Resolve or provision the user ─────────────────────────────────
        $user = match ($channel) {
            self::CHANNEL_EMAIL => $this->userRepository->findByEmail($identifier),
            self::CHANNEL_SMS   => $this->userRepository->findByPhone($identifier),
            default             => null,
        };

        if ($user === null) {
            if (! $this->config->autoProvision) {
                return AuthResult::failed(
                    errorCode:    'USER_NOT_FOUND',
                    errorMessage: "No account associated with this {$channel} address.",
                    latencyMs:    (hrtime(as_num: true) - $start) / 1_000_000,
                );
            }

            // Just-in-time provisioning (first passwordless login)
            $user = $this->userRepository->create(
                match ($channel) {
                    self::CHANNEL_EMAIL => ['email' => $identifier],
                    self::CHANNEL_SMS   => ['phone' => $identifier],
                    default             => [],
                }
            );

            $this->logger->info('OtpProvider: auto-provisioned user on first OTP login', [
                'user_id' => $user->getAuthIdentifier(),
                'channel' => $channel,
            ]);
        }

        // ── 6. MFA gate ──────────────────────────────────────────────────────
        if ($this->config->mfaEnabled && $user->hasMfaEnabled()) {
            $mfaToken = bin2hex(random_bytes(32));

            return AuthResult::pendingMfa(
                user:     $user,
                mfaToken: $mfaToken,
                meta:     ['provider' => $this->name(), 'channel' => $channel],
            );
        }

        // ── 7. Issue token ────────────────────────────────────────────────────
        $token = $this->tokenService->issue($user, ['otp_channel' => $channel]);

        $this->logger->info('OtpProvider: OTP authentication successful', [
            'user_id' => $user->getAuthIdentifier(),
            'channel' => $channel,
        ]);

        return AuthResult::authenticated(
            user:      $user,
            token:     $token,
            meta:      ['provider' => $this->name(), 'channel' => $channel],
            latencyMs: (hrtime(as_num: true) - $start) / 1_000_000,
        );
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Generate a CSPRNG OTP of the configured digit length.
     * random_int() is cryptographically secure on all PHP 8.3 platforms.
     */
    private function generateOtp(): string
    {
        $max = (int) str_repeat('9', $this->config->otpLength);
        return str_pad(
            (string) random_int(0, $max),
            $this->config->otpLength,
            '0',
            STR_PAD_LEFT,
        );
    }

    /**
     * Compute HMAC-SHA256 of the OTP using the server-side secret.
     * We store this digest — plaintext is never persisted.
     */
    private function hmac(string $otp): string
    {
        return hash_hmac('sha256', $otp, $this->config->otpHmacSecret);
    }

    /** Deterministic cache key for OTP storage (hashed to prevent identifier leakage). */
    private function otpCacheKey(string $identifier): string
    {
        return self::CACHE_OTP . hash('sha256', $identifier);
    }

    /** Deterministic cache key for attempt counter. */
    private function attemptCacheKey(string $identifier): string
    {
        return self::CACHE_ATTEMPTS . hash('sha256', $identifier);
    }

    /**
     * Resolve the identifier and channel from credentials.
     *
     * PHP 8.3: returns a typed tuple via array shape.
     *
     * @param  array<string, mixed> $credentials
     * @return array{0: string, 1: string}  [identifier, channel]
     * @throws GhostAuthException
     */
    private function resolveIdentifier(array $credentials): array
    {
        return match (true) {
            ! empty($credentials['email']) => [
                strtolower(trim((string) $credentials['email'])),
                self::CHANNEL_EMAIL,
            ],
            ! empty($credentials['phone']) => [
                trim((string) $credentials['phone']),
                self::CHANNEL_SMS,
            ],
            default => throw new GhostAuthException(
                "OtpProvider: credentials must contain 'email' or 'phone'."
            ),
        };
    }

    /**
     * Mask an identifier for safe logging.
     *
     * 'jane@example.com' → 'ja**@example.com'
     * '+8801712345678'   → '+880171****5678'
     */
    private function mask(string $identifier): string
    {
        if (str_contains($identifier, '@')) {
            [$local, $domain] = explode('@', $identifier, 2);
            return substr($local, 0, 2) . str_repeat('*', max(0, strlen($local) - 2)) . '@' . $domain;
        }

        return substr($identifier, 0, 7)
            . str_repeat('*', max(0, strlen($identifier) - 11))
            . substr($identifier, -4);
    }

    /** @throws GhostAuthException */
    private function guardAvailable(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException('OtpProvider is disabled.');
        }
    }
}
