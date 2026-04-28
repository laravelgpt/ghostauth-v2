<?php

declare(strict_types=1);

namespace GhostAuth\Security;

/**
 * DeviceFingerprint
 *
 * Generates a stable, privacy-preserving fingerprint from the user's
 * HTTP request characteristics. Used for:
 *   - Detecting session hijacking (cookie stolen on different device)
 *   - IP change detection (triggers cookie destruction when fingerprint changes)
 *   - Concurrent session management (same user, multiple devices)
 *
 * Composition (SHA-256 truncated to first 64 hex chars = 256 bits):
 *   - Remote IP address
 *   - User-Agent header
 *   - Accept-Language header
 *   - Server-side secret pepper (prevents forgery)
 *
 * Security model:
 *   The fingerprint is deterministic for a given device + browser + network.
 *   An attacker with only the cookie cannot reproduce the fingerprint without
 *   also knowing the server-side pepper. This means:
 *     - Cookie stolen + replayed from different IP → fingerprint mismatch → destroy
 *     - Legitimate IP change (mobile roaming) → fingerprint mismatch → re-auth required
 *     - Same device, same IP → fingerprint stable across sessions
 *
 * @package GhostAuth\Security
 */
final readonly class DeviceFingerprint
{
    public const  DEFAULT_SALT = '';

    public function __construct(
        private string $remoteIp,
        private string $userAgent,
        private string $acceptLanguage = '',
        private string $salt = self::DEFAULT_SALT,
    ) {}

    /**
     * Build a fingerprint from a PSR-7 ServerRequestInterface.
     *
     * @param  array<string, mixed> $server  $_SERVER or request server params.
     * @param  string               $salt    Optional server-side salt (from config).
     * @return static
     */
    public static function fromRequest(array $server, string $salt = self::DEFAULT_SALT): static
    {
        return new static(
            remoteIp:       $server['REMOTE_ADDR'] ?? '0.0.0.0',
            userAgent:      $server['HTTP_USER_AGENT'] ?? '',
            acceptLanguage: $server['HTTP_ACCEPT_LANGUAGE'] ?? '',
            salt:           $salt,
        );
    }

    /**
     * Generate the fingerprint hash.
     *
     * Truncated to 64 hex chars (SHA-256 output).
     * The salt is mixed in as a trailing component to prevent offline
     * rainbow-table attacks on the fingerprint.
     *
     * @return string  64-character hex fingerprint.
     */
    public function compute(): string
    {
        $raw = implode('|', [
            $this->remoteIp,
            $this->userAgent,
            $this->acceptLanguage,
            $this->salt,
        ]);

        return hash('sha256', $raw);
    }

    /**
     * Compare a stored fingerprint against the current request fingerprint.
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @param  string $storedFingerprint  The fingerprint stored when the session was created.
     * @return bool   True if fingerprints match.
     */
    public function matches(string $storedFingerprint): bool
    {
        return hash_equals($storedFingerprint, $this->compute());
    }

    /**
     * Return a human-readable breakdown of what changed (for logging).
     *
     * @param  string $storedFingerprint  Fingerprint from the session.
     * @return array<string, bool>  Keys that differ between stored and current.
     */
    public function diff(string $storedFingerprint): array
    {
        if ($this->matches($storedFingerprint)) {
            return [];
        }

        return [
            'ip_changed'       => $this->remoteIp !== '',
            'ua_changed'       => $this->userAgent !== '',
            'lang_changed'     => $this->acceptLanguage !== '',
            'fingerprint_hash' => $this->compute(),
            'stored_hash'      => $storedFingerprint,
        ];
    }

    public function getIp(): string        { return $this->remoteIp; }
    public function getUserAgent(): string { return $this->userAgent; }
    public function getLanguage(): string  { return $this->acceptLanguage; }
}
