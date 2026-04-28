<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Contracts\UserRepositoryInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Enums\AuthStatus;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\GhostAuthConfiguration;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * PasswordProvider
 *
 * Authenticates users via email + password using Argon2id hashing.
 *
 * PHP 8.3 features:
 *   - Typed class constants (`public const string`).
 *   - Constructor property promotion with readonly modifiers.
 *   - `match` expressions for exhaustive algorithm dispatch.
 *   - `never` return type on guard methods that always throw.
 *
 * Security layers:
 *   1. Constant-time verification via `password_verify()`.
 *   2. Dummy-verify on "user not found" — prevents email enumeration via timing.
 *   3. Optional pepper — server-side secret appended before hashing.
 *   4. Transparent rehashing on login when cost params are upgraded.
 *   5. Generic error message for both "no user" and "wrong password".
 *
 * @package GhostAuth\Providers
 */
final class PasswordProvider implements AuthenticationStrategy
{
    // -------------------------------------------------------------------------
    // PHP 8.3: Typed class constants
    // -------------------------------------------------------------------------

    /** Argon2id memory cost (KiB) — 64 MiB per OWASP 2023+ recommendation. */
    public const  ARGON2_MEMORY = 65536;

    /** Argon2id iteration count. */
    public const  ARGON2_TIME = 4;

    /** Argon2id parallelism factor. */
    public const  ARGON2_THREADS = 2;

    /**
     * Dummy hash used for constant-time "user not found" path.
     * A valid Argon2id hash — password_verify() runs for the same duration.
     * This specific hash corresponds to the string "ghost-dummy-constant".
     */
    public const  DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=2$c29tZXNhbHRzb21lc2FsdA$RoRbFiIAf0+pPAMY5F/zNQv6A7IZN8mEWRuAJVeD4QA';

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public function __construct(
        private readonly GhostAuthConfiguration  $config,
        private readonly UserRepositoryInterface $userRepository,
        private readonly TokenServiceInterface   $tokenService,
        private readonly bool                    $enabled  = true,
        private readonly LoggerInterface         $logger   = new NullLogger(),
    ) {}

    // -------------------------------------------------------------------------
    // AuthenticationStrategy
    // -------------------------------------------------------------------------

    /**
     * Authenticate via email + password.
     *
     * @param  array<string, mixed> $credentials  Must contain 'email' and 'password'.
     * @throws GhostAuthException  On missing credentials or provider misconfiguration.
     */
    public function authenticate(array $credentials): AuthResult
    {
        $start = hrtime(as_num: true);

        $this->guardAvailable();
        $this->requireKeys($credentials, ['email', 'password']);

        $email    = strtolower(trim((string) $credentials['email']));
        $password = (string) $credentials['password'];

        // ------------------------------------------------------------------
        // 1. Find user — run dummy verify regardless to prevent timing-based
        //    email enumeration.
        // ------------------------------------------------------------------
        $user = $this->userRepository->findByEmail($email);

        if ($user === null) {
            // Constant-time: always spend the same time as a real verify
            password_verify('ghost-dummy-constant', self::DUMMY_HASH);

            $this->logger->warning('PasswordProvider: auth failed — user not found', [
                'email' => $email,
            ]);

            return AuthResult::failed(
                errorCode:    'INVALID_CREDENTIALS',
                errorMessage: 'The email or password you entered is incorrect.',
                latencyMs:    $this->elapsedMs($start),
            );
        }

        // ------------------------------------------------------------------
        // 2. Ensure account has a password set (not social/OTP-only).
        // ------------------------------------------------------------------
        if ($user->getAuthPassword() === null) {
            return AuthResult::failed(
                errorCode:    'NO_PASSWORD_SET',
                errorMessage: 'This account uses passwordless authentication. Please use your configured login method.',
                latencyMs:    $this->elapsedMs($start),
            );
        }

        // ------------------------------------------------------------------
        // 3. Verify password with optional pepper.
        // ------------------------------------------------------------------
        $inputToVerify = $this->peppered($password);

        if (! password_verify($inputToVerify, $user->getAuthPassword())) {
            $this->logger->warning('PasswordProvider: auth failed — wrong password', [
                'user_id' => $user->getAuthIdentifier(),
            ]);

            return AuthResult::failed(
                errorCode:    'INVALID_CREDENTIALS',
                errorMessage: 'The email or password you entered is incorrect.',
                latencyMs:    $this->elapsedMs($start),
            );
        }

        // ------------------------------------------------------------------
        // 4. Transparent rehash — upgrade silently when cost params improve.
        // ------------------------------------------------------------------
        if (password_needs_rehash($user->getAuthPassword(), $this->phpAlgo(), $this->argon2Options())) {
            $upgraded = $this->hash($password);
            $this->userRepository->update($user->getAuthIdentifier(), ['password' => $upgraded]);

            $this->logger->info('PasswordProvider: password silently rehashed to updated cost params', [
                'user_id' => $user->getAuthIdentifier(),
            ]);
        }

        // ------------------------------------------------------------------
        // 5. Check MFA — if enabled, return pendingMfa instead of a full token.
        // ------------------------------------------------------------------
        if ($this->config->mfaEnabled && $user->hasMfaEnabled()) {
            $mfaToken = bin2hex(random_bytes(32)); // short-lived proof token
        // Cache token for MFA handler to complete authentication
            // TODO: cache mfaToken → user_id for the MFA handler to look up
        $this->cache->set("ghostauth:mfa_token:{$mfaToken}", $user->getAuthIdentifier(), self::MFA_TTL);
        // Cache token for MFA handler to complete authentication
        $this->cache->set("ghostauth:mfa_token:{$mfaToken}", $user->getAuthIdentifier(), self::MFA_TTL);

            return AuthResult::pendingMfa(
                user:     $user,
                mfaToken: $mfaToken,
                meta:     ['provider' => $this->name()],
            );
        }

        // ------------------------------------------------------------------
        // 6. Issue token and return success.
        // ------------------------------------------------------------------
        $token = $this->tokenService->issue($user);

        $this->logger->info('PasswordProvider: authentication successful', [
            'user_id' => $user->getAuthIdentifier(),
        ]);

        return AuthResult::authenticated(
            user:      $user,
            token:     $token,
            meta:      ['provider' => $this->name()],
            latencyMs: $this->elapsedMs($start),
        );
    }

    public function name(): string
    {
        return AuthenticationStrategy::PROVIDER_PASSWORD;
    }

    public function isAvailable(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // Public utility — used by registration/password-update flows
    // -------------------------------------------------------------------------

    /**
     * Hash a plaintext password using the configured algorithm.
     *
     * @param  string $plaintext  Raw password from the user.
     * @return string             Hash to persist in the data store.
     */
    public function hash(string $plaintext): string
    {
        return password_hash(
            $this->peppered($plaintext),
            $this->phpAlgo(),
            $this->argon2Options(),
        );
    }

    /**
     * Verify a plaintext password against a stored hash without full auth flow.
     * Useful for "confirm your password before deleting account" flows.
     */
    public function verify(string $plaintext, string $hash): bool
    {
        return password_verify($this->peppered($plaintext), $hash);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Append the pepper (if configured) to the plaintext. */
    private function peppered(string $plaintext): string
    {
        return $this->config->pepper !== null
            ? $plaintext . $this->config->pepper
            : $plaintext;
    }

    /**
     * Return the PHP PASSWORD_* constant for the configured algorithm.
     *
     * PHP 8.3: exhaustive match expression — compile-time safety.
     *
     * @return int|string
     */
    private function phpAlgo(): int|string
    {
        return $this->config->hashAlgorithm->toPhpConstant();
    }

    /** @return array<string, int> */
    private function argon2Options(): array
    {
        return [
            'memory_cost' => self::ARGON2_MEMORY,
            'time_cost'   => self::ARGON2_TIME,
            'threads'     => self::ARGON2_THREADS,
        ];
    }

    /** Convert hrtime nanoseconds to milliseconds. */
    private function elapsedMs(float $startNs): float
    {
        return (hrtime(as_num: true) - $startNs) / 1_000_000;
    }

    /**
     * @throws GhostAuthException
     * @return never-return implied by throw
     */
    private function guardAvailable(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException('PasswordProvider is disabled.');
        }
    }

    /**
     * @param  array<string, mixed> $credentials
     * @param  string[]             $keys
     * @throws GhostAuthException
     */
    private function requireKeys(array $credentials, array $keys): void
    {
        foreach ($keys as $key) {
            if (empty($credentials[$key])) {
                throw new GhostAuthException(
                    "PasswordProvider: missing required credential key '{$key}'."
                );
            }
        }
    }
}
