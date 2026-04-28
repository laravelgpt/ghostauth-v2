<?php

declare(strict_types=1);

namespace GhostAuth\DTO;

/**
 * OtpPayload
 *
 * Readonly DTO representing a generated, not-yet-dispatched OTP.
 * Passed from the OTP generator to the sender and cache layer.
 *
 * PHP 8.3: `readonly class` — entire object is deeply immutable.
 *
 * @package GhostAuth\DTO
 */
readonly class OtpPayload
{
    public const  CHANNEL_EMAIL = 'email';
    public const  CHANNEL_SMS   = 'sms';

    /**
     * @param string $plaintext    The raw N-digit OTP shown to the user.
     * @param string $hmac         HMAC-SHA256 digest of $plaintext (what we store in cache).
     * @param string $recipient    Email address or E.164 phone number.
     * @param string $channel      Delivery channel: 'email' | 'sms'.
     * @param int    $expiresAt    Unix timestamp when this OTP expires.
     * @param string $cacheKey     The cache key under which the HMAC is stored.
     */
    public function __construct(
        public readonly string $plaintext,
        public readonly string $hmac,
        public readonly string $recipient,
        public readonly string $channel,
        public readonly int    $expiresAt,
        public readonly string $cacheKey,
    ) {}

    /** Seconds remaining until expiry at call time. */
    public function expiresInSeconds(): int
    {
        return max(0, $this->expiresAt - time());
    }

    /** Whether the OTP is still within its validity window. */
    public function isExpired(): bool
    {
        return time() > $this->expiresAt;
    }
}
