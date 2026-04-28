<?php

declare(strict_types=1);

namespace GhostAuth\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * MagicLink
 *
 * Passwordless authentication via magic links sent to email.
 *
 * Flow:
 *   1. User enters email → generate magic link token → send email
 *   2. User clicks link → token verified → authenticated
 *
 * Security:
 *   - 256-bit CSPRNG tokens
 *   - Short TTL (15 minutes default)
 *   - Single-use (deleted after first use)
 *   - Tied to specific email and IP (optional)
 *   - IP binding prevents link forwarding attacks
 *
 * @package GhostAuth\Security
 */
class MagicLink
{
    public const TOKEN_PREFIX = 'ghostauth:magic:';
    public const DEFAULT_TTL  = 900; // 15 minutes

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int            $ttl = self::DEFAULT_TTL,
        private readonly bool           $bindIp = true,
    ) {}

    /**
     * Generate a magic link token.
     *
     * @param  string $email  The email address to authenticate.
     * @param  mixed  $userId The user ID.
     * @param  string $ip     Client IP (for binding).
     * @return string         The magic link token.
     */
    public function generateToken(string $email, mixed $userId, string $ip = ''): string
    {
        $token = bin2hex(random_bytes(32));
        $key   = self::TOKEN_PREFIX . hash('sha256', $token);

        // Invalidate previous magic links for this user
        $this->invalidateAll($userId);

        $this->cache->set($key, [
            'email'   => $email,
            'user_id' => $userId,
            'ip'      => $this->bindIp ? $ip : null,
            'created' => time(),
        ], $this->ttl);

        return $token;
    }

    /**
     * Verify and consume a magic link token.
     *
     * @param  string      $token        The token from the link.
     * @param  string|null $currentIp    Current request IP (for binding check).
     * @return array{success: bool, email: string|null, user_id: mixed, error: string|null}
     */
    public function verify(string $token, ?string $currentIp = null): array
    {
        $key  = self::TOKEN_PREFIX . hash('sha256', $token);
        $data = $this->cache->get($key);

        if (! is_array($data)) {
            return [
                'success' => false,
                'email'   => null,
                'user_id' => null,
                'error'   => 'Invalid or expired magic link.',
            ];
        }

        // IP binding check
        if ($this->bindIp && isset($data['ip']) && $data['ip'] !== null && $currentIp !== null) {
            if ($data['ip'] !== $currentIp) {
                $this->cache->delete($key); // Consume the token even on failure
                return [
                    'success' => false,
                    'email'   => null,
                    'user_id' => null,
                    'error'   => 'Magic link was generated from a different IP address.',
                ];
            }
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
     * Generate a full magic link URL.
     */
    public function generateUrl(string $token, string $baseUrl, string $param = 'token'): string
    {
        $sep = str_contains($baseUrl, '?') ? '&' : '?';
        return $baseUrl . $sep . $param . '=' . urlencode($token);
    }

    /** Invalidate all pending magic links for a user. */
    public function invalidateAll(mixed $userId): void
    {
        $indexKey = 'ghostauth:magic:index:' . (string) $userId;
        /** @var string[] $tokens */
        $tokens = (array) $this->cache->get($indexKey, []);

        foreach ($tokens as $t) {
            $this->cache->delete(self::TOKEN_PREFIX . hash('sha256', $t));
        }

        $this->cache->delete($indexKey);
    }
}
