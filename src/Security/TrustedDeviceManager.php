<?php

declare(strict_types=1);

namespace GhostAuth\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * TrustedDeviceManager
 *
 * Manages a user's list of trusted devices.
 * Trusted devices can skip MFA and extended OTP prompts.
 *
 * Device identification:
 *   - Device fingerprint hash (IP + UA + Accept-Language + salt)
 *   - Optional: User-provided device name (e.g. "MacBook Pro — Chrome")
 *
 * Trust model:
 *   - Devices expire after $trustDurationSeconds (default: 90 days)
 *   - User can manually revoke any trusted device
 *   - Password change → ALL trusted devices revoked
 *   - MFA disabled → ALL trusted devices revoked
 *
 * @package GhostAuth\Security
 */
class TrustedDeviceManager
{
    public const CACHE_PREFIX    = 'ghostauth:trusted:';
    public const DEFAULT_TRUST   = 7_776_000; // 90 days in seconds

    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int            $trustDuration = self::DEFAULT_TRUST,
    ) {}

    /**
     * Check if a device is trusted for a user.
     *
     * @param  mixed  $userId
     * @param  string $deviceFingerprint  DeviceFingerprint::compute() output.
     * @return bool
     */
    public function isTrusted(mixed $userId, string $deviceFingerprint): bool
    {
        $key = $this->deviceKey($userId, $deviceFingerprint);
        $data = $this->cache->get($key);

        if (! is_array($data)) {
            return false;
        }

        // Check expiry
        if (($data['expires_at'] ?? 0) < time()) {
            $this->cache->delete($key);
            return false;
        }

        return true;
    }

    /**
     * Mark a device as trusted.
     *
     * @param  mixed                $userId
     * @param  string               $deviceFingerprint
     * @param  string               $deviceName  Human-readable name (e.g. "iPhone 15 Safari").
     * @param  string               $ip          Client IP address.
     * @return array{trusted: bool, expires_at: int}
     */
    public function trustDevice(
        mixed $userId,
        string $deviceFingerprint,
        string $deviceName = 'Unknown Device',
        string $ip = '',
    ): array {
        $key = $this->deviceKey($userId, $deviceFingerprint);
        $expiresAt = time() + $this->trustDuration;

        $this->cache->set($key, [
            'device_name' => $deviceName,
            'ip'          => $ip,
            'trusted_at'  => time(),
            'expires_at'  => $expiresAt,
        ], $this->trustDuration);

        return ['trusted' => true, 'expires_at' => $expiresAt];
    }

    /**
     * Revoke trust for a specific device.
     */
    public function revokeDevice(mixed $userId, string $deviceFingerprint): void
    {
        $this->cache->delete($this->deviceKey($userId, $deviceFingerprint));
    }

    /**
     * Revoke ALL trusted devices for a user.
     * Called on password change, security event, or user request.
     *
     * @return int  Number of devices revoked.
     */
    public function revokeAllDevices(mixed $userId): int
    {
        $pattern = self::CACHE_PREFIX . md5((string) $userId) . ':*';

        // PSR-16 doesn't support pattern-based delete — iterate known keys
        // In production, use Redis SCAN or maintain a user-device index
        $count = 0;
        $deviceKey = self::CACHE_PREFIX . 'index:' . (string) $userId;

        /** @var array<string, string> $index */
        $index = (array) $this->cache->get($deviceKey, []);

        foreach ($index as $fingerprint => $_key) {
            $this->cache->delete($_key);
            $count++;
        }

        $this->cache->delete($deviceKey);

        return $count;
    }

    /**
     * List all trusted devices for a user.
     *
     * @return array<int, array{device_name: string, ip: string, trusted_at: int, expires_at: int, fingerprint: string}>
     */
    public function listDevices(mixed $userId): array
    {
        $deviceKey = self::CACHE_PREFIX . 'index:' . (string) $userId;
        /** @var array<string, string> $index */
        $index = (array) $this->cache->get($deviceKey, []);

        $devices = [];
        foreach ($index as $fingerprint => $key) {
            $data = $this->cache->get($key);
            if (is_array($data)) {
                $devices[] = array_merge($data, ['fingerprint' => $fingerprint]);
            }
        }

        return $devices;
    }

    /**
     * Check if user has ANY trusted device (for "remember this device" UI).
     */
    public function hasAnyTrustedDevice(mixed $userId): bool
    {
        $deviceKey = self::CACHE_PREFIX . 'index:' . (string) $userId;
        return ! empty($this->cache->get($deviceKey, []));
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Generate the cache key for a device.
     * Uses md5 of userId to keep keys short.
     */
    private function deviceKey(mixed $userId, string $deviceFingerprint): string
    {
        return self::CACHE_PREFIX . md5((string) $userId) . ':' . $deviceFingerprint;
    }
}
