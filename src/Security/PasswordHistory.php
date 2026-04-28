<?php

declare(strict_types=1);

namespace GhostAuth\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * PasswordHistory
 *
 * Prevents password reuse by maintaining a history of password hashes per user.
 * When a user changes password, check against the last N passwords.
 *
 * Security:
 *   - Stores only salted hashes (not plaintext)
 *   - Per-user history with LRU eviction
 *   - Configurable history size (default: last 5 passwords)
 *
 * @package GhostAuth\Security
 */
class PasswordHistory
{
    public const HISTORY_PREFIX = 'ghostauth:pw_history:';
    public const DEFAULT_SIZE   = 5; // Remember last 5 passwords

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int            $historySize = self::DEFAULT_SIZE,
    ) {}

    /**
     * Add a new password to the user's history.
     * Called after successful password change.
     *
     * @param  mixed  $userId     The user ID.
     * @param  string $password   The new password (plaintext) to hash and store.
     */
    public function add(mixed $userId, string $password): void
    {
        $userKey = self::HISTORY_PREFIX . (string) $userId;
        $history = $this->getHistory($userId);

        // Hash the password (same as main system would use)
        $hashed = password_hash($password, PASSWORD_ARGON2ID);

        // Prepend to history (most recent first)
        array_unshift($history, $hashed);

        // Trim to configured size
        if (count($history) > $this->historySize) {
            $history = array_slice($history, 0, $this->historySize);
        }

        // Store updated history
        $this->cache->set($userKey, $history, 0); // 0 = no expiry (until explicitly removed)
    }

    /**
     * Check if a password matches any in the user's history.
     *
     * @param  mixed  $userId     The user ID.
     * @param  string $password   The password to check (plaintext).
     * @return bool               True if password is in history (should not be reused).
     */
    public function exists(mixed $userId, string $password): bool
    {
        $history = $this->getHistory($userId);

        foreach ($history as $hashed) {
            if (password_verify($password, $hashed)) {
                return true; // Password found in history
            }
        }

        return false; // Password not in history (safe to use)
    }

    /**
     * Get the password history for a user.
     *
     * @param  mixed $userId  The user ID.
     * @return string[]       Array of password hashes (most recent first).
     */
    private function getHistory(mixed $userId): array
    {
        $userKey = self::HISTORY_PREFIX . (string) $userId;
        return (array) $this->cache->get($userKey, []);
    }

    /**
     * Clear password history for a user.
     * Useful when explicitly resetting password policy or on account deletion.
     *
     * @param  mixed $userId  The user ID.
     */
    public function clear(mixed $userId): void
    {
        $userKey = self::HISTORY_PREFIX . (string) $userId;
        $this->cache->delete($userKey);
    }

    /**
     * Get the number of passwords in history for a user.
     *
     * @param  mixed $userId  The user ID.
     * @return int            Number of passwords in history (0 to historySize).
     */
    public function count(mixed $userId): int
    {
        return count($this->getHistory($userId));
    }
}
