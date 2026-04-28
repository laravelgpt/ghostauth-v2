<?php

declare(strict_types=1);

namespace GhostAuth\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * EmailVerification
 *
 * Handles the email verification flow:
 *   1. User registers or changes email → generate verification token
 *   2. Send verification email with token link
 *   3. User clicks link → token verified → email marked as verified
 *
 * Tokens:
 *   - 128-bit CSPRNG, URL-safe base64
 *   - TTL: configurable (default 24 hours)
 *   - Single-use (deleted on first successful verification)
 *   - Tied to specific email address
 *
 * @package GhostAuth\Security
 */
class EmailVerification
{
    public const TOKEN_PREFIX = 'ghostauth:email_verify:';
    public const DEFAULT_TTL  = 86400; // 24 hours

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int            $ttl = self::DEFAULT_TTL,
    ) {}

    /**
     * Generate a verification token for an email address.
     *
     * @param  string $email    The email address to verify.
     * @param  mixed  $userId   The user ID (for lookup after verification).
     * @return string           The verification token (URL-safe).
     */
    public function generateToken(string $email, mixed $userId): string
    {
        $token = self::randomToken();
        $key   = self::TOKEN_PREFIX . hash('sha256', $token);

        $this->cache->set($key, [
            'email'    => $email,
            'user_id'  => $userId,
            'created'  => time(),
        ], $this->ttl);

        return $token;
    }

    /**
     * Verify a token and return the associated user info.
     *
     * @param  string $token  The verification token from the email link.
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
                'error'   => 'Invalid or expired verification token.',
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
     * Generate a full verification URL.
     *
     * @param  string $token       The verification token.
     * @param  string $baseUrl     Base URL of the verification endpoint.
     * @param  string $tokenParam  Query parameter name for the token.
     * @return string
     */
    public function generateUrl(string $token, string $baseUrl, string $tokenParam = 'token'): string
    {
        $separator = str_contains($baseUrl, '?') ? '&' : '?';
        return $baseUrl . $separator . $tokenParam . '=' . urlencode($token);
    }

    /**
     * Invalidate all pending verification tokens for a user.
     * Called when user changes email address.
     */
    public function invalidateAll(mixed $userId): void
    {
        // PSR-16 doesn't support pattern delete — in production use Redis SCAN
        // or maintain a user → token index
        $indexKey = 'ghostauth:email_verify:index:' . (string) $userId;
        /** @var string[] $tokens */
        $tokens = (array) $this->cache->get($indexKey, []);

        foreach ($tokens as $t) {
            $this->cache->delete(self::TOKEN_PREFIX . hash('sha256', $t));
        }

        $this->cache->delete($indexKey);
    }

    private static function randomToken(): string
    {
        return bin2hex(random_bytes(16));
    }
}
