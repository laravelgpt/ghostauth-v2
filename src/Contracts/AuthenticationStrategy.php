<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

use GhostAuth\DTO\AuthResult;

/**
 * AuthenticationStrategy
 *
 * The central Strategy Pattern contract for all authentication methods.
 * GhostAuth's AuthManager dispatches exclusively through this interface —
 * adding a new auth method requires only implementing this contract.
 *
 * PHP 8.3: typed class constants on an interface.
 *
 * @package GhostAuth\Contracts
 */
interface AuthenticationStrategy
{
    // -------------------------------------------------------------------------
    // PHP 8.3: Typed interface constants
    // -------------------------------------------------------------------------

    /** Well-known provider name constants — used as AuthManager keys. */
    public const  PROVIDER_PASSWORD = 'password';
    public const  PROVIDER_OTP      = 'otp';
    public const  PROVIDER_GOOGLE   = 'google';
    public const  PROVIDER_GITHUB   = 'github';
    public const  PROVIDER_OIDC     = 'oidc';

    /**
     * Attempt authentication with the given credentials.
     *
     * Each strategy defines what $credentials must contain:
     *   password: ['email', 'password']
     *   otp:      ['email' OR 'phone'] for send; + ['otp'] for verify
     *   oauth:    ['code', 'state'] after redirect callback
     *   oidc:     ['id_token', 'state', 'nonce'] after callback
     *
     * @param  array<string, mixed> $credentials  Strategy-specific credential map.
     * @return AuthResult                         Structured, immutable result.
     *
     * @throws \GhostAuth\Exceptions\GhostAuthException  On infrastructure/config errors only.
     *                                                    Auth failures return AuthResult::failed().
     */
    public function authenticate(array $credentials): AuthResult;

    /**
     * Unique name that identifies this strategy.
     * Must match one of the PROVIDER_* constants for built-in strategies.
     */
    public function name(): string;

    /**
     * Whether this strategy is configured and ready to handle requests.
     * AuthManager MUST call this before dispatching.
     */
    public function isAvailable(): bool;
}
