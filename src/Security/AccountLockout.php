<?php

declare(strict_types=1);

namespace GhostAuth\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * AccountLockout
 *
 * Protects against brute-force attacks by locking accounts after
 * a configurable number of consecutive failed authentication attempts.
 *
 * Lockout mechanics:
 *   - After $maxAttempts failures, the account is locked for $lockoutSeconds.
 *   - Each subsequent failure while locked EXTENDS the lockout (exponential backoff).
 *   - A successful authentication resets the failure counter.
 *   - Lockout is per-identifier (email), not per-IP (targeted attacks).
 *   - Admin unlock bypasses the lockout entirely.
 *
 * @package GhostAuth\Security
 */
class AccountLockout
{
    public const PREFIX_FAILURES = 'ghostauth:lockout:failures:';
    public const PREFIX_LOCKED   = 'ghostauth:lockout:locked:';
    public const DEFAULT_MAX     = 5;
    public const DEFAULT_LOCKOUT = 900; // 15 minutes

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int            $maxAttempts     = self::DEFAULT_MAX,
        private readonly int            $lockoutSeconds  = self::DEFAULT_LOCKOUT,
        private readonly int            $backoffMultiplier = 2, // 2x lockout each time
    ) {}

    /**
     * Record a failed authentication attempt.
     *
     * @param  string $identifier  Email address or username.
     * @return array{
     *     locked: bool,
     *     remaining_attempts: int,
     *     lockout_until: int|null,
     *     lockout_seconds: int|null,
     * }
     */
    public function recordFailure(string $identifier): array
    {
        $failKey  = self::PREFIX_FAILURES . hash('sha256', $identifier);
        $lockKey  = self::PREFIX_LOCKED . hash('sha256', $identifier);

        // Increment failure counter
        $failures = (int) $this->cache->get($failKey, 0);
        $failures++;
        $this->cache->set($failKey, $failures, $this->lockoutSeconds * 4);

        $remaining = max(0, $this->maxAttempts - $failures);

        if ($failures >= $this->maxAttempts) {
            // Account is locked — compute lockout duration with backoff
            $lockoutRounds = intdiv($failures - $this->maxAttempts, $this->maxAttempts) + 1;
            $lockoutDuration = $this->lockoutSeconds * (int) pow($this->backoffMultiplier, $lockoutRounds - 1);
            $lockoutUntil    = time() + $lockoutDuration;

            $this->cache->set($lockKey, $lockoutUntil, $lockoutDuration);

            return [
                'locked'           => true,
                'remaining_attempts' => 0,
                'lockout_until'    => $lockoutUntil,
                'lockout_seconds'  => $lockoutDuration,
            ];
        }

        return [
            'locked'           => false,
            'remaining_attempts' => $remaining,
            'lockout_until'    => null,
            'lockout_seconds'  => null,
        ];
    }

    /**
     * Check if an account is currently locked.
     *
     * @param  string $identifier
     * @return array{locked: bool, lockout_until: int|null, lockout_seconds: int|null}
     */
    public function isLocked(string $identifier): array
    {
        $lockKey = self::PREFIX_LOCKED . hash('sha256', $identifier);
        $lockoutUntil = $this->cache->get($lockKey);

        if ($lockoutUntil === null || (int) $lockoutUntil <= time()) {
            return ['locked' => false, 'lockout_until' => null, 'lockout_seconds' => null];
        }

        return [
            'locked'          => true,
            'lockout_until'   => (int) $lockoutUntil,
            'lockout_seconds' => (int) $lockoutUntil - time(),
        ];
    }

    /**
     * Reset the failure counter (called on successful authentication).
     */
    public function reset(string $identifier): void
    {
        $failKey = self::PREFIX_FAILURES . hash('sha256', $identifier);
        $lockKey = self::PREFIX_LOCKED . hash('sha256', $identifier);

        $this->cache->delete($failKey);
        $this->cache->delete($lockKey);
    }

    /**
     * Admin override — unlock an account immediately.
     */
    public function adminUnlock(string $identifier): void
    {
        $this->reset($identifier);
    }

    /**
     * Get the current failure count for monitoring/admin dashboards.
     */
    public function getFailureCount(string $identifier): int
    {
        $failKey = self::PREFIX_FAILURES . hash('sha256', $identifier);
        return (int) $this->cache->get($failKey, 0);
    }
}
