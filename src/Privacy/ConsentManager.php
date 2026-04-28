<?php

declare(strict_types=1);

namespace GhostAuth\Privacy;

use Psr\SimpleCache\CacheInterface;

/**
 * ConsentManager
 *
 * Manages user consent for data processing (GDPR, CCPA, etc.).
 * Tracks what users have consented to and when.
 *
 * Consent types:
 *   - marketing: Receive promotional emails/SMS
 *   - analytics: Allow usage analytics collection
 *   - profiling: Allow behavioral profiling
 *   - sharing: Allow data sharing with third parties
 *   - biometric: Allow biometric data (WebAuthn/FaceID/TouchID)
 *   - location: Allow location-based services
 *
 * @package GhostAuth\Privacy
 */
class ConsentManager
{
    public const CONSENT_PREFIX = 'ghostauth:consent:';
    public const VERSION_KEY    = 'version';

    /** All known consent types */
    public const CONSENT_TYPES = [
        'marketing',
        'analytics',
        'profiling',
        'sharing',
        'biometric',
        'location',
    ];

    public function __construct(
        private readonly CacheInterface $cache,
    ) {}

    /**
     * Record user consent for specific purposes.
     *
     * @param  mixed   $userId    The user ID.
     * @param  string[] $types    Array of consent types being granted.
     * @param  int     $version   Consent version (for tracking policy changes).
     * @return void
     */
    public function grantConsent(mixed $userId, array $types, int $version = 1): void
    {
        $key = self::CONSENT_PREFIX . (string) $userId;

        $consent = [
            self::VERSION_KEY => $version,
            'granted_at'      => time(),
            'types'           => array_fill_keys(
                array_intersect($types, self::CONSENT_TYPES),
                true
            ),
        ];

        // Ensure all known types are present (false if not granted)
        foreach (self::CONSENT_TYPES as $type) {
            if (! isset($consent['types'][$type])) {
                $consent['types'][$type] = false;
            }
        }

        $this->cache->set($key, $consent, 0); // No expiry - lasts until changed
    }

    /**
     * Withdraw consent for specific purposes.
     *
     * @param  mixed   $userId  The user ID.
     * @param  string[] $types  Array of consent types to withdraw.
     * @return void
     */
    public function withdrawConsent(mixed $userId, array $types): void
    {
        $key    = self::CONSENT_PREFIX . (string) $userId;
        $record = $this->getConsent($userId);

        if ($record === null) {
            return; // No consent record to modify
        }

        // Set specified types to false
        foreach ($types as $type) {
            if (in_array($type, self::CONSENT_TYPES, true)) {
                $record['types'][$type] = false;
            }
        }

        $record['withdrawn_at'] = time();
        $this->cache->set($key, $record, 0);
    }

    /**
     * Check if user has given consent for a specific purpose.
     *
     * @param  mixed   $userId  The user ID.
     * @param  string  $type    The consent type to check.
     * @return bool             True if consented, false otherwise.
     */
    public function hasConsent(mixed $userId, string $type): bool
    {
        $record = $this->getConsent($userId);

        if ($record === null) {
            return false; // No consent record = not consented
        }

        return isset($record['types'][$type]) && $record['types'][$type] === true;
    }

    /**
     * Get the full consent record for a user.
     *
     * @param  mixed $userId  The user ID.
     * @return array|null     Consent record or null if none exists.
     */
    public function getConsent(mixed $userId): ?array
    {
        $key = self::CONSENT_PREFIX . (string) $userId;
        return $this->cache->get($key);
    }

    /**
     * Check if user has any consent record.
     *
     * @param  mixed $userId  The user ID.
     * @return bool
     */
    public function hasConsentRecord(mixed $userId): bool
    {
        return $this->getConsent($userId) !== null;
    }

    /**
     * Get timestamp when consent was granted.
     *
     * @param  mixed $userId  The user ID.
     * @return int|null       Timestamp or null if no consent.
     */
    public function getConsentGrantedAt(mixed $userId): ?int
    {
        $record = $this->getConsent($userId);
        return $record ? ($record['granted_at'] ?? null) : null;
    }

    /**
     * Get consent version (for detecting when policy changed).
     *
     * @param  mixed $userId  The user ID.
     * @return int|null       Version or null if no consent.
     */
    public function getConsentVersion(mixed $userId): ?int
    {
        $record = $this->getConsent($userId);
        return $record ? ($record[self::VERSION_KEY] ?? null) : null;
    }

    /**
     * Require that user has given specific consent before proceeding.
     * Throws exception if consent not given.
     *
     * @param  mixed   $userId  The user ID.
     * @param  string  $type    The consent type required.
     * @param  string  $feature Feature name for error message.
     * @throws \GhostAuth\Exceptions\GhostAuthException
     */
    public function requireConsent(mixed $userId, string $type, string $feature = 'this feature'): void
    {
        if (! $this->hasConsent($userId, $type)) {
            throw new \GhostAuth\Exceptions\GhostAuthException(
                sprintf('Consent required for %s: please enable %s consent in your settings.', $feature, $type)
            );
        }
    }

    /**
     * Get all consent types the user has granted.
     *
     * @param  mixed $userId  The user ID.
     * @return string[]       Array of granted consent types.
     */
    public function getGrantedTypes(mixed $userId): array
    {
        $record = $this->getConsent($userId);

        if ($record === null) {
            return [];
        }

        $granted = [];
        foreach ($record['types'] as $type => $grantedFlag) {
            if ($grantedFlag === true) {
                $granted[] = $type;
            }
        }

        return $granted;
    }

    /**
     * Get all consent types the user has NOT granted (denied or not asked).
     *
     * @param  mixed $userId  The user ID.
     * @return string[]       Array of not-granted consent types.
     */
    public function getDeniedTypes(mixed $userId): array
    {
        $record = $this->getConsent($userId);

        if ($record === null) {
            return self::CONSENT_TYPES; // All types not consented if no record
        }

        $denied = [];
        foreach ($record['types'] as $type => $grantedFlag) {
            if ($grantedFlag !== true) {
                $denied[] = $type;
            }
        }

        return $denied;
    }
}
