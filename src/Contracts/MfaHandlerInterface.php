<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

use GhostAuth\DTO\AuthResult;

/**
 * MfaHandlerInterface
 *
 * PHP 8.3 / Architecture note:
 * MFA is implemented as a Decorator over any AuthenticationStrategy.
 * The MfaDecorator wraps a primary strategy, calls it first, then —
 * if the user has MFA enabled — returns AuthResult::pendingMfa()
 * instead of the final token.
 *
 * A separate MFA verification call (TOTP code, backup code, etc.) then
 * calls handle() below to complete the second factor.
 *
 * This keeps MFA logic fully orthogonal to primary auth strategies.
 *
 * @package GhostAuth\Contracts
 */
interface MfaHandlerInterface
{
    /**
     * Verify the MFA challenge response and issue a final session token.
     *
     * @param  string               $mfaToken    Short-lived token from AuthResult::pendingMfa().
     * @param  array<string, mixed> $credentials MFA-specific credentials (e.g. ['totp_code' => '123456']).
     * @return AuthResult
     */
    public function handle(string $mfaToken, array $credentials): AuthResult;

    /**
     * Enroll a user in MFA (generate secret, return QR code URL, etc.)
     *
     * @param  AuthenticatableInterface $user
     * @return array<string, mixed>  Enrollment data (qr_url, backup_codes, etc.)
     */
    public function enroll(AuthenticatableInterface $user): array;

    /** Whether MFA handling is configured and active. */
    public function isAvailable(): bool;
}
