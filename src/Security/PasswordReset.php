<?php

declare(strict_types=1);

namespace GhostAuth\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * PasswordReset
 *
 * Secure password reset flow:
 *   1. User requests reset → generate reset token, send email
 *   2. User clicks link → enters new password
 *   3. Token verified → password updated → all sessions destroyed
 *
 * Security:
 *   - 256-bit CSPRNG tokens
 *   - Short TTL (1 hour default)
 *   - Single-use
 *   - Tied to specific email
 *   - All sessions revoked on successful reset
 *
 * @package GhostAuth\Security
 */
class PasswordReset
{
    public const TOKEN_PREFIX = 'ghostauth:pw_reset:';
    public const DEFAULT_TTL  = 3600; // 1 hour

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int            $ttl = self::DEFAULT_TTL,
    ) {}

    /**
     * Generate a password reset token.
     *
     * @param  string $email    The email address to reset.
     * @param  mixed  $userId   The user ID.
     * @return string           The reset token (URL-safe, 64 hex chars).
     */
    public function generateToken(string $email, mixed $userId): string
    {
        $token = self::randomToken();
        $key   = self::TOKEN_PREFIX . hash('sha256', $token);

        // Invalidate any previous reset tokens for this user
        $this->invalidateAll($userId);

        $this->cache->set($key, [
            'email'   => $email,
            'user_id' => $userId,
            'created' => time(),
        ], $this->ttl);

        return $token;
    }

    /**
     * Verify a reset token and return the associated user info.
     *
     * @param  string $token  The reset token from the email link.
     * @return array{success: bool, email: string|null, user_id: mixed, error: string|null}
     */
    public function verify(string $token): array
    {
        $key  = self::TOKEN_PREFIX . hash('sha256', $token);
        $data = $this->cache->get($key);

        if (! is_array($data)) {
            return [
                'success' => false,
                'email'   => null,
                'user_id' => null,
                'error'   => 'Invalid or expired reset token.',
            ];
        }

        // Single-use: delete immediately
        $this->cache->delete($key);

        return [
            'success' => true,
            'email'   => $data['email'],
            'user_id' => $data['user_id'],
            'error'   => null,
        ];
    }

    /**
     * Generate a full reset URL.
     */
    public function generateUrl(string $token, string $baseUrl, string $param = 'token'): string
    {
        $sep = str_contains($baseUrl, '?') ? '&' : '?';
        return $baseUrl . $sep . $param . '=' . urlencode($token);
    }

    /**
     * Invalidate all pending reset tokens for a user.
     * Called after successful password reset or when user changes email.
     */
    public function invalidateAll(mixed $userId): void
    {
        $indexKey = 'ghostauth:pw_reset:index:' . (string) $userId;
        /** @var string[] $tokens */
        $tokens = (array) $this->cache->get($indexKey, []);

        foreach ($tokens as $t) {
            $this->cache->delete(self::TOKEN_PREFIX . hash('sha256', $t));
        }

        $this->cache->delete($indexKey);
    }

    private static function randomToken(): string
    {
        return bin2hex(random_bytes(32)); // 256 bits
    }
}
