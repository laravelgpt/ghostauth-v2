<?php

declare(strict_types=1);

namespace GhostAuth\Enums;

/**
 * AuthStatus
 *
 * Represents all possible states an authentication attempt can resolve to.
 * Used in AuthResult DTO for exhaustive match/switch handling in consuming code.
 *
 * @package GhostAuth\Enums
 */
enum AuthStatus: string
{
    /** Authentication fully succeeded — token issued. */
    case Authenticated = 'authenticated';

    /** OTP dispatched — awaiting verification in a second request. */
    case PendingOtp = 'pending_otp';

    /** MFA required — primary auth succeeded but second factor needed. */
    case PendingMfa = 'pending_mfa';

    /** OAuth redirect generated — awaiting provider callback. */
    case PendingOAuth = 'pending_oauth';

    /** Authentication failed — invalid credentials, expired OTP, etc. */
    case Failed = 'failed';

    /** Provider is disabled or misconfigured. */
    case Unavailable = 'unavailable';

    // -------------------------------------------------------------------------
    // PHP 8.3: typed constant on an enum
    // -------------------------------------------------------------------------

    /** All "pending" statuses — useful for middleware checks. */
    public const  PENDING = [
        self::PendingOtp,
        self::PendingMfa,
        self::PendingOAuth,
    ];

    /** Whether this status represents a successful, fully authenticated session. */
    public function isAuthenticated(): bool
    {
        return $this === self::Authenticated;
    }

    /** Whether further action is required before a session token is issued. */
    public function isPending(): bool
    {
        return in_array($this, self::PENDING, strict: true);
    }

    /** Whether the auth attempt was definitively rejected. */
    public function isFailed(): bool
    {
        return $this === self::Failed || $this === self::Unavailable;
    }
}
