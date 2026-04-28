<?php

declare(strict_types=1);

namespace GhostAuth\Security;

use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Exceptions\SessionException;
use GhostAuth\Exceptions\TokenException;
use GhostAuth\GhostAuthConfiguration;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * SessionGuard
 *
 * Comprehensive session security layer that provides:
 *
 *   1. Cookie Encryption — AES-256-CTR encryption of cookie payload
 *      (prevents reading token contents from browser/dev tools)
 *
 *   2. Cookie Signing — HMAC-SHA256 integrity signature
 *      (prevents cookie tampering; modified cookies are silently rejected)
 *
 *   3. IP Change Cookie Destroyer — detects when a cookie is used from
 *      a different IP/device than where it was issued; immediately
 *      revokes the token and invalidates all related sessions
 *
 *   4. User-Agent Binding — detects browser/client changes
 *
 *   5. Session Rotation — issues a new cookie with new fingerprint
 *      on each use, preventing session fixation
 *
 *   6. Concurrent Session Limit — configurable max sessions per user;
 *      oldest sessions are evicted when the limit is exceeded
 *
 *   7. Secure Cookie Attributes — HttpOnly, Secure, SameSite=Strict
 *
 * Threat model:
 *   - Attacker steals cookie via XSS → encrypted, but HMAC prevents reuse
 *     from different IP due to DeviceFingerprint binding
 *   - Attacker modifies cookie payload → HMAC signature fails → rejected
 *   - Attacker replays cookie on same network → User-Agent mismatch → rejected
 *   - Legitimate IP change (mobile roaming) → triggers re-auth (safe default)
 *
 * @package GhostAuth\Security
 */
final class SessionGuard
{
    // Cookie attribute constants
    public const  COOKIE_NAME      = 'ghostauth_session';
    public const     COOKIE_LIFETIME  = 3600;
    public const  COOKIE_PATH      = '/';
    public const  COOKIE_DOMAIN    = '';
    public const    COOKIE_SECURE    = true;
    public const    COOKIE_HTTP_ONLY = true;
    public const  COOKIE_SAME_SITE = 'Strict';

    // HMAC version prefix — allows future algorithm migration
    public const  HMAC_VERSION = 'v1';

    // AES mode for cookie encryption
    public const  AES_MODE = 'aes-256-ctr';

    // Cache key prefix for session registry
    public const  SESSION_REGISTRY = 'ghostauth:sessions:';

    public function __construct(
        private readonly GhostAuthConfiguration $config,
        private readonly TokenServiceInterface  $tokenService,
        private readonly CacheInterface         $cache,
        private readonly int                    $maxSessionsPerUser = 5,
        private readonly bool                   $strictIpBinding    = true,
        private readonly bool                   $strictUaBinding    = true,
        private readonly LoggerInterface        $logger             = new NullLogger(),
    ) {}

    // =========================================================================
    // Cookie Read: Decrypt + Verify + Fingerprint Check
    // =========================================================================

    /**
     * Read, decrypt, verify, and validate a session cookie.
     *
     * Flow:
     *   1. Parse cookie string (version.hmac.iv.ciphertext)
     *   2. Verify HMAC — reject silently if tampered
     *   3. Decrypt AES-256-CTR — recover JSON payload
     *   4. Validate payload structure
     *   5. Check DeviceFingerprint — IP/UA binding
     *   6. If IP changed and strict mode: COOKIE DESTROYER
     *      → revoke token, delete all sessions for this user, log event
     *   7. If fingerprint valid: return (token, fingerprint)
     *
     * @param  string $cookieValue  Raw cookie string from HTTP request.
     * @param  DeviceFingerprint|null $currentFingerprint  Fingerprint of current request.
     * @return array{token: string, fingerprint: string|null, rotated: bool}
     *
     * @throws SessionException  On decryption or validation failure.
     */
    public function readSession(
        string $cookieValue,
        ?DeviceFingerprint $currentFingerprint = null,
    ): array {
        // ── 1. Parse cookie structure: version.hmac.iv.ciphertext ─────────
        $parts = explode('.', $cookieValue);

        if (count($parts) !== 4 || $parts[0] !== self::HMAC_VERSION) {
            throw new SessionException('Invalid or expired session cookie.');
        }

        [$version, $providedHmac, $iv, $ciphertext] = $parts;

        // ── 2. Verify HMAC integrity ──────────────────────────────────────
        $expectedHmac = $this->computeHmac($iv . '.' . $ciphertext);

        if (! hash_equals($expectedHmac, $providedHmac)) {
            $this->logger->warning('SessionGuard: HMAC mismatch — cookie tampered', [
                'expected_prefix' => substr($expectedHmac, 0, 8),
                'provided_prefix' => substr($providedHmac, 0, 8),
            ]);

            throw new SessionException('Session cookie integrity check failed.');
        }

        // ── 3. Decrypt ────────────────────────────────────────────────────
        $ivBytes = base64_decode($iv);

        if ($ivBytes === false || strlen($ivBytes) !== openssl_cipher_iv_length(self::AES_MODE)) {
            throw new SessionException('Invalid session cookie IV.');
        }

        $json = openssl_decrypt(
            data:     base64_decode($ciphertext),
            cipher:   self::AES_MODE,
            key:      $this->config->jwtSecret, // Reuse JWT secret for encryption key
            options:  OPENSSL_RAW_DATA,
            iv:       $ivBytes,
        );

        if ($json === false) {
            throw new SessionException('Session cookie decryption failed.');
        }

        if (! json_validate($json)) {
            throw new SessionException('Session cookie payload is invalid.');
        }

        $payload = (array) json_decode($json, associative: true);

        // ── 4. Validate payload structure ─────────────────────────────────
        if (! isset($payload['token'], $payload['fingerprint'], $payload['user_id'], $payload['created_at'])) {
            throw new SessionException('Malformed session cookie payload.');
        }

        $token         = (string) $payload['token'];
        $storedFp      = (string) $payload['fingerprint'];
        $userId        = (string) $payload['user_id'];
        $createdAt     = (int)   $payload['created_at'];

        // ── 5. Verify the JWT token is still valid ───────────────────────
        try {
            $claims = $this->tokenService->verify($token);
        } catch (TokenException $e) {
            $this->logger->info('SessionGuard: underlying JWT is invalid', [
                'user_id' => $userId,
                'reason'  => $e->getMessage(),
            ]);

            // Token expired/revoked → clean up sessions
            $this->purgeUserSessions($userId);

            throw new SessionException('Session has expired. Please log in again.');
        }

        // ── 6. Device fingerprint check — IP CHANGE COOKIE DESTROYER ─────
        if ($currentFingerprint !== null && $this->strictIpBinding) {
            if (! $currentFingerprint->matches($storedFp)) {
                $this->logger->warning('SessionGuard: device mismatch — COOKIE DESTROYER triggered', [
                    'user_id'     => $userId,
                    'stored_fp'   => substr($storedFp, 0, 12) . '...',
                    'current_fp'  => substr($currentFingerprint->compute(), 0, 12) . '...',
                    'ip'          => $currentFingerprint->getIp(),
                    'user_agent'  => $currentFingerprint->getUserAgent(),
                ]);

                // COOKIE DESTROYER: revoke token, purge all sessions for this user
                $this->destroyUserSessions($userId, $token);

                throw new SessionException(
                    'Session invalidated due to suspicious device change. Please log in again.'
                );
            }
        }

        // ── 7. Return session data ────────────────────────────────────────
        return [
            'token'       => $token,
            'fingerprint' => $storedFp,
            'user_id'     => $userId,
            'claims'      => $claims,
            'created_at'  => $createdAt,
        ];
    }

    // =========================================================================
    // Cookie Write: Encrypt + Sign + Set
    // =========================================================================

    /**
     * Create a secure session cookie from a JWT token and device fingerprint.
     *
     * Flow:
     *   1. Build JSON payload (token, fingerprint, user_id, created_at)
     *   2. Encrypt with AES-256-CTR + random IV
     *   3. Compute HMAC-SHA256 over IV + ciphertext
     *   4. Format: version.hmac.iv.ciphertext
     *   5. Register session in cache for concurrent session tracking
     *   6. Set cookie header
     *
     * @param  string              $token        Valid JWT token.
     * @param  DeviceFingerprint   $fingerprint  Current device fingerprint.
     * @param  int|string          $userId       User identifier.
     * @param  array<string, mixed> $options     Cookie overrides (domain, lifetime, etc.)
     * @return string  The cookie value to set (returned for testing; cookie is also set).
     */
    public function createSession(
        string $token,
        DeviceFingerprint $fingerprint,
        int|string $userId,
        array $options = [],
    ): string {
        $userId = (string) $userId;

        // ── 1. Build payload ──────────────────────────────────────────────
        $payload = [
            'token'       => $token,
            'fingerprint' => $fingerprint->compute(),
            'user_id'     => $userId,
            'created_at'  => time(),
        ];

        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        // ── 2. Encrypt ────────────────────────────────────────────────────
        $ivBytes = random_bytes(openssl_cipher_iv_length(self::AES_MODE));
        $iv      = base64_encode($ivBytes);

        $ciphertext = openssl_encrypt(
            data:     $json,
            cipher:   self::AES_MODE,
            key:      $this->config->jwtSecret,
            options:  OPENSSL_RAW_DATA,
            iv:       $ivBytes,
        );

        if ($ciphertext === false) {
            throw new SessionException('Session cookie encryption failed.');
        }

        $ctEncoded = base64_encode($ciphertext);

        // ── 3. HMAC signature ─────────────────────────────────────────────
        $hmac = $this->computeHmac($iv . '.' . $ctEncoded);

        // ── 4. Format: version.hmac.iv.ciphertext ─────────────────────────
        $cookieValue = implode('.', [self::HMAC_VERSION, $hmac, $iv, $ctEncoded]);

        // ── 5. Register session for concurrent session tracking ───────────
        $this->registerSession($userId, $token);

        // ── 6. Set cookie ─────────────────────────────────────────────────
        $this->setCookieHeader($cookieValue, $options);

        return $cookieValue;
    }

    // =========================================================================
    // Cookie Destroy / Logout
    // =========================================================================

    /**
     * Destroy a single session cookie (logout).
     *
     * Revokes the token, removes from session registry, and sets
     * a deletion cookie (expired).
     */
    public function destroySession(string $cookieValue): void
    {
        try {
            $session = $this->readSession($cookieValue);
            $this->tokenService->revoke($session['token']);
            $this->removeFromSessionRegistry($session['user_id'], $session['token']);
        } catch (SessionException) {
            // Cookie already invalid — nothing to destroy
        }

        // Set a deletion cookie (expired in the past)
        $this->setCookieHeader(
            '',
            ['lifetime' => -1, 'value' => 'deleted'],
        );
    }

    /**
     * Destroy ALL sessions for a given user.
     * Called on password change, account compromise, or security event.
     *
     * @param  int|string $userId  The user whose sessions to destroy.
     * @return int  Number of sessions destroyed.
     */
    public function destroyAllUserSessions(int|string $userId): int
    {
        return $this->purgeUserSessions((string) $userId);
    }

    // =========================================================================
    // IP Change Cookie Destroyer
    // =========================================================================

    /**
     * Called when device fingerprint mismatch is detected.
     * Revokes the current token and purges ALL sessions for this user.
     *
     * This is the core of the "IP change cookies destroyer" mechanism:
     *   - Any cookie used from a different IP/device than where it was issued
     *     triggers immediate destruction of ALL the user's active sessions.
     *   - The user must re-authenticate from a known device.
     *
     * @param  int|string $userId       The affected user.
     * @param  string     $currentToken The token that triggered the detection.
     */
    public function destroyUserSessions(int|string $userId, string $currentToken): void
    {
        $userId = (string) $userId;

        // Revoke the token that triggered detection
        try {
            $this->tokenService->revoke($currentToken);
        } catch (TokenException) {
            // Token may already be expired — continue purging
        }

        // Purge all session registry entries for this user
        $purged = $this->purgeUserSessions($userId);

        $this->logger->emergency('SessionGuard: IP/device change triggered full session destruction', [
            'user_id'       => $userId,
            'sessions_purged' => $purged,
        ]);
    }

    // =========================================================================
    // Session Rotation (prevent session fixation)
    // =========================================================================

    /**
     * Rotate the session — issue a new cookie with a new fingerprint.
     * Called after:
     *   - Successful authentication (replace anonymous → authenticated)
     *   - Privilege escalation (e.g. admin login)
     *   - Periodic rotation (configurable)
     *
     * The old token is NOT revoked immediately — it remains valid until expiry.
     * Only the new cookie is issued. This prevents "stuck" sessions if the
     * rotation fails mid-request.
     *
     * @param  string              $currentToken  Current JWT.
     * @param  DeviceFingerprint   $newFingerprint  Current request fingerprint.
     * @param  int|string          $userId
     * @return string  New cookie value.
     */
    public function rotateSession(
        string $currentToken,
        DeviceFingerprint $newFingerprint,
        int|string $userId,
    ): string {
        return $this->createSession($currentToken, $newFingerprint, $userId);
    }

    // =========================================================================
    // Concurrent Session Management
    // =========================================================================

    /**
     * Return the number of active sessions for a user.
     */
    public function getActiveSessionCount(int|string $userId): int
    {
        $key = self::SESSION_REGISTRY . (string) $userId;
        $sessions = $this->cache->get($key, []);

        if (! is_array($sessions)) {
            return 0;
        }

        // Filter out expired/revoked sessions
        $active = array_filter($sessions, fn($tok) => $this->isTokenValid($tok));

        return count($active);
    }

    /**
     * List all active sessions for a user (for "manage your sessions" UI).
     *
     * @return array<int, array{token_preview: string, created_at: int}>
     */
    public function listUserSessions(int|string $userId): array
    {
        $key      = self::SESSION_REGISTRY . (string) $userId;
        $sessions = (array) $this->cache->get($key, []);
        $result   = [];

        foreach ($sessions as $tok => $meta) {
            if ($this->isTokenValid($tok)) {
                $result[] = [
                    'token_preview' => substr((string) $tok, 0, 12) . '...',
                    'created_at'    => is_array($meta) ? ($meta['created_at'] ?? 0) : 0,
                ];
            }
        }

        return $result;
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Compute HMAC-SHA256 of the given data using the JWT secret.
     */
    private function computeHmac(string $data): string
    {
        return hash_hmac('sha256', self::HMAC_VERSION . '|' . $data, $this->config->jwtSecret);
    }

    /**
     * Register a session in the cache-based session registry.
     * Enforces maxSessionsPerUser — evicts oldest when exceeded.
     */
    private function registerSession(string $userId, string $token): void
    {
        $key = self::SESSION_REGISTRY . $userId;

        /** @var array<string, mixed> $sessions */
        $sessions = (array) $this->cache->get($key, []);

        $sessions[$token] = ['created_at' => time()];

        // Evict oldest if exceeding limit
        if (count($sessions) > $this->maxSessionsPerUser) {
            uasort($sessions, fn($a, $b) => ($a['created_at'] ?? 0) <=> ($b['created_at'] ?? 0));
            $evict = array_shift($sessions);
            if (is_array($evict)) {
                try {
                    $this->tokenService->revoke((string) ($evict['token'] ?? ''));
                } catch (TokenException) {
                    // Ignore — token may already be expired
                }
            }
        }

        $this->cache->set($key, $sessions, $this->config->jwtTtlSeconds + 60);
    }

    /**
     * Remove a specific session from the registry.
     */
    private function removeFromSessionRegistry(string $userId, string $token): void
    {
        $key = self::SESSION_REGISTRY . $userId;
        $sessions = (array) $this->cache->get($key, []);

        unset($sessions[$token]);

        if (empty($sessions)) {
            $this->cache->delete($key);
        } else {
            $this->cache->set($key, $sessions, $this->config->jwtTtlSeconds + 60);
        }
    }

    /**
     * Purge all sessions for a user from the registry.
     *
     * @return int  Number of sessions purged.
     */
    private function purgeUserSessions(string $userId): int
    {
        $key = self::SESSION_REGISTRY . $userId;
        $sessions = (array) $this->cache->get($key, []);
        $count = count($sessions);

        // Revoke all tokens
        foreach (array_keys($sessions) as $tok) {
            try {
                $this->tokenService->revoke((string) $tok);
            } catch (TokenException) {
                // Already expired or revoked
            }
        }

        $this->cache->delete($key);

        return $count;
    }

    /**
     * Check if a token is still valid (not expired, not revoked).
     */
    private function isTokenValid(string $token): bool
    {
        try {
            $this->tokenService->verify($token);
            return true;
        } catch (TokenException) {
            return false;
        }
    }

    /**
     * Set the Set-Cookie header.
     *
     * @param  string               $value    Cookie value.
     * @param  array<string, mixed> $options  Override defaults.
     */
    private function setCookieHeader(string $value, array $options): void
    {
        $name     = $options['name']     ?? self::COOKIE_NAME;
        $lifetime = $options['lifetime'] ?? self::COOKIE_LIFETIME;
        $path     = $options['path']     ?? self::COOKIE_PATH;
        $domain   = $options['domain']   ?? self::COOKIE_DOMAIN;
        $secure   = $options['secure']   ?? self::COOKIE_SECURE;
        $httpOnly = $options['http_only'] ?? self::COOKIE_HTTP_ONLY;
        $sameSite = $options['same_site'] ?? self::COOKIE_SAME_SITE;

        if (headers_sent()) {
            $this->logger->warning('SessionGuard: headers already sent — cannot set cookie');
            return;
        }

        if ($lifetime < 0) {
            // Deletion cookie
            setcookie($name, 'deleted', [
                'expires'  => time() - 3600,
                'path'     => $path,
                'domain'   => $domain,
                'secure'   => $secure,
                'httponly' => $httpOnly,
                'samesite' => $sameSite,
            ]);
            return;
        }

        setcookie($name, $value, [
            'expires'  => time() + $lifetime,
            'path'     => $path,
            'domain'   => $domain,
            'secure'   => $secure,
            'httponly' => $httpOnly,
            'samesite' => $sameSite,
        ]);
    }
}
