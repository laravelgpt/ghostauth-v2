<?php

declare(strict_types=1);

namespace GhostAuth\DTO;

use GhostAuth\Contracts\AuthenticatableInterface;
use GhostAuth\Enums\AuthStatus;

/**
 * AuthResult
 *
 * Immutable Data Transfer Object representing the outcome of any authentication attempt.
 *
 * PHP 8.3 features:
 *   - `readonly class` — all properties are deeply immutable after construction.
 *   - Typed class constants: `public const  VERSION`.
 *   - Constructor promotion with nullable intersection-ready types.
 *   - `AuthStatus` backed enum for exhaustive result matching in consuming code.
 *
 * Pattern note:
 *   AuthResult is a pure value object — it carries data only, no logic.
 *   All factory methods are static to keep construction intent explicit.
 *
 * Example consuming code (PHP 8.3 match expression):
 *   $response = match ($result->status) {
 *       AuthStatus::Authenticated => redirect('/dashboard'),
 *       AuthStatus::PendingOtp    => render('otp-form'),
 *       AuthStatus::PendingMfa    => render('mfa-form'),
 *       AuthStatus::Failed        => render('login', ['error' => $result->errorMessage]),
 *       default                   => abort(503),
 *   };
 *
 * @package GhostAuth\DTO
 */
readonly class AuthResult
{
    // -------------------------------------------------------------------------
    // PHP 8.3: Typed class constants on a readonly class
    // -------------------------------------------------------------------------

    public const  SCHEMA_VERSION = '1.0';

    /**
     * @param AuthStatus                   $status        The resolution state of this auth attempt.
     * @param AuthenticatableInterface|null $user          The authenticated user (null on failure/pending).
     * @param string|null                   $token         Issued JWT or session token (null on failure/pending).
     * @param string|null                   $errorCode     Machine-readable error code (null on success).
     * @param string|null                   $errorMessage  Human-readable description (null on success).
     * @param array<string, mixed>          $meta          Contextual extras (expiry, channel, provider, etc.).
     * @param float                         $latencyMs     Auth operation duration in milliseconds (observability).
     */
    public function __construct(
        public readonly AuthStatus                    $status,
        public readonly ?AuthenticatableInterface     $user         = null,
        public readonly ?string                       $token        = null,
        public readonly ?string                       $errorCode    = null,
        public readonly ?string                       $errorMessage = null,
        public readonly array                         $meta         = [],
        public readonly float                         $latencyMs    = 0.0,
    ) {}

    // -------------------------------------------------------------------------
    // Static factory methods — named constructors for each semantic outcome
    // -------------------------------------------------------------------------

    /**
     * Create a fully-authenticated result with a token.
     *
     * @param  AuthenticatableInterface $user
     * @param  string                   $token
     * @param  array<string, mixed>     $meta
     * @param  float                    $latencyMs
     * @return static
     */
    public static function authenticated(
        AuthenticatableInterface $user,
        string $token,
        array $meta = [],
        float $latencyMs = 0.0,
    ): static {
        return new static(
            status:    AuthStatus::Authenticated,
            user:      $user,
            token:     $token,
            meta:      $meta,
            latencyMs: $latencyMs,
        );
    }

    /**
     * Create an OTP-pending result (Phase 1 of passwordless flow).
     *
     * @param  array<string, mixed> $meta  e.g. ['channel' => 'email', 'expires_in' => 300]
     * @param  float                $latencyMs
     * @return static
     */
    public static function pendingOtp(array $meta = [], float $latencyMs = 0.0): static
    {
        return new static(
            status:       AuthStatus::PendingOtp,
            errorCode:    'OTP_DISPATCHED',
            errorMessage: 'A verification code has been sent. Please submit it to complete login.',
            meta:         $meta,
            latencyMs:    $latencyMs,
        );
    }

    /**
     * Create an MFA-pending result (primary auth succeeded; second factor required).
     *
     * @param  AuthenticatableInterface $user       The user who passed primary auth.
     * @param  string                   $mfaToken   Short-lived token proving primary auth succeeded.
     * @param  array<string, mixed>     $meta
     * @return static
     */
    public static function pendingMfa(
        AuthenticatableInterface $user,
        string $mfaToken,
        array $meta = [],
    ): static {
        return new static(
            status:       AuthStatus::PendingMfa,
            user:         $user,
            token:        $mfaToken,
            errorCode:    'MFA_REQUIRED',
            errorMessage: 'Primary authentication successful. Please complete multi-factor verification.',
            meta:         $meta,
        );
    }

    /**
     * Create an OAuth redirect result (consumer should redirect user to $meta['redirect_url']).
     *
     * @param  string               $redirectUrl  The OAuth authorization URL.
     * @param  array<string, mixed> $meta
     * @return static
     */
    public static function pendingOAuth(string $redirectUrl, array $meta = []): static
    {
        return new static(
            status:       AuthStatus::PendingOAuth,
            errorCode:    'OAUTH_REDIRECT',
            errorMessage: 'Redirect the user to the authorization URL in meta.redirect_url.',
            meta:         array_merge(['redirect_url' => $redirectUrl], $meta),
        );
    }

    /**
     * Create a failed authentication result.
     *
     * @param  string               $errorCode     Machine-readable failure code.
     * @param  string               $errorMessage  Human-readable description.
     * @param  array<string, mixed> $meta
     * @param  float                $latencyMs
     * @return static
     */
    public static function failed(
        string $errorCode,
        string $errorMessage,
        array $meta = [],
        float $latencyMs = 0.0,
    ): static {
        return new static(
            status:       AuthStatus::Failed,
            errorCode:    $errorCode,
            errorMessage: $errorMessage,
            meta:         $meta,
            latencyMs:    $latencyMs,
        );
    }

    // -------------------------------------------------------------------------
    // Convenience accessors
    // -------------------------------------------------------------------------

    /** @return bool  True only when fully authenticated with a token. */
    public function isAuthenticated(): bool
    {
        return $this->status->isAuthenticated();
    }

    /** @return bool  True when further input is expected from the user. */
    public function isPending(): bool
    {
        return $this->status->isPending();
    }

    /** @return bool  True when the attempt was definitively rejected. */
    public function isFailed(): bool
    {
        return $this->status->isFailed();
    }

    /**
     * Return a safe, loggable representation (token replaced with first 8 chars + '...').
     *
     * @return array<string, mixed>
     */
    public function toLogContext(): array
    {
        return [
            'status'        => $this->status->value,
            'user_id'       => $this->user?->getAuthIdentifier(),
            'error_code'    => $this->errorCode,
            'latency_ms'    => round($this->latencyMs, 2),
            'token_preview' => $this->token !== null
                ? substr($this->token, 0, 8) . '...'
                : null,
        ];
    }
}
