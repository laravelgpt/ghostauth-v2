<?php

declare(strict_types=1);

namespace GhostAuth\Events;

/**
 * SecurityEvent
 *
 * Immutable event record for all authentication-related security events.
 * Used for audit logging, notifications, webhook dispatch, and anomaly detection.
 *
 * @package GhostAuth\Events
 */
readonly class SecurityEvent
{
    // -------------------------------------------------------------------------
    // Event type constants
    // -------------------------------------------------------------------------

    /** User successfully authenticated */
    public const AUTH_SUCCESS     = 'auth.success';

    /** User failed authentication (wrong password, invalid OTP) */
    public const AUTH_FAILURE     = 'auth.failure';

    /** New device detected during login */
    public const DEVICE_NEW       = 'device.new';

    /** Device marked as trusted by user */
    public const DEVICE_TRUSTED   = 'device.trusted';

    /** Device untrusted (removed from trusted list) */
    public const DEVICE_UNTRUSTED = 'device.untrusted';

    /** Account locked due to failed attempts */
    public const ACCOUNT_LOCKED   = 'account.locked';

    /** Account unlocked (by admin or after lockout expires) */
    public const ACCOUNT_UNLOCKED = 'account.unlocked';

    /** Password changed */
    public const PASSWORD_CHANGED = 'password.changed';

    /** Password reset requested */
    public const PASSWORD_RESET_REQUEST = 'password.reset.request';

    /** Password reset completed */
    public const PASSWORD_RESET_COMPLETE = 'password.reset.complete';

    /** Email verification requested */
    public const EMAIL_VERIFY_REQUEST = 'email.verify.request';

    /** Email verified */
    public const EMAIL_VERIFIED = 'email.verified';

    /** MFA enabled for account */
    public const MFA_ENABLED    = 'mfa.enabled';

    /** MFA disabled for account */
    public const MFA_DISABLED   = 'mfa.disabled';

    /** MFA backup code used */
    public const MFA_BACKUP_USED = 'mfa.backup.used';

    /** Session revoked (logout) */
    public const SESSION_REVOKED = 'session.revoked';

    /** All sessions destroyed (security event) */
    public const SESSIONS_DESTROYED = 'sessions.destroyed';

    /** IP change cookie destroyer triggered */
    public const COOKIE_DESTROYED = 'cookie.destroyed';

    /** Magic link sent */
    public const MAGIC_LINK_SENT = 'magic.sent';

    /** Magic link used */
    public const MAGIC_LINK_USED = 'magic.used';

    /** Brute force attack detected */
    public const BRUTE_FORCE_DETECTED = 'brute.force';

    /** Password found in breach database */
    public const PASSWORD_BREACHED = 'password.breached';

    /** Suspicious login (anomaly detected) */
    public const ANOMALY_DETECTED = 'anomaly.detected';

    // -------------------------------------------------------------------------
    // Severity levels
    // -------------------------------------------------------------------------

    public const SEVERITY_INFO     = 'info';
    public const SEVERITY_WARNING  = 'warning';
    public const SEVERITY_CRITICAL = 'critical';
    public const SEVERITY_EMERGENCY = 'emergency';

    /**
     * @param string               $type        Event type constant value.
     * @param string               $severity    Severity level.
     * @param mixed                $userId      User identifier (null for pre-auth events).
     * @param array<string, mixed> $metadata    Contextual data (IP, user agent, device, etc.).
     * @param int                  $timestamp   Unix timestamp of the event.
     * @param string               $requestId   Unique request ID for correlation.
     */
    public function __construct(
        public string $type,
        public string $severity,
        public mixed  $userId = null,
        public array  $metadata = [],
        public int    $timestamp = 0,
        public string $requestId = '',
    ) {
        if ($this->timestamp === 0) {
            $this->timestamp = time();
        }
        if ($this->requestId === '') {
            $this->requestId = bin2hex(random_bytes(8));
        }
    }

    /**
     * Get the PSR-3 log level for this event.
     */
    public function getLogLevel(): string
    {
        return match ($this->severity) {
            self::SEVERITY_INFO      => 'info',
            self::SEVERITY_WARNING   => 'warning',
            self::SEVERITY_CRITICAL  => 'error',
            self::SEVERITY_EMERGENCY => 'critical',
            default                  => 'info',
        };
    }

    /**
     * Convert to an array for JSON serialization, database storage, or webhook delivery.
     */
    public function toArray(): array
    {
        return [
            'type'       => $this->type,
            'severity'   => $this->severity,
            'user_id'    => $this->userId,
            'metadata'   => $this->metadata,
            'timestamp'  => $this->timestamp,
            'request_id' => $this->requestId,
        ];
    }

    /**
     * Reconstruct from array.
     */
    public static function fromArray(array $data): static
    {
        return new static(
            type:       $data['type'],
            severity:   $data['severity'],
            userId:     $data['user_id'] ?? null,
            metadata:   $data['metadata'] ?? [],
            timestamp:  $data['timestamp'] ?? 0,
            requestId:  $data['request_id'] ?? '',
        );
    }
}
