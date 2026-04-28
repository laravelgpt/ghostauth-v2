<?php

declare(strict_types=1);

namespace GhostAuth\Decorators;

use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\Contracts\MfaHandlerInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Enums\AuthStatus;

/**
 * MfaDecorator
 *
 * Wraps any AuthenticationStrategy with a transparent MFA gate.
 *
 * Architecture (Decorator Pattern):
 *   ┌───────────────────────┐
 *   │      MfaDecorator     │  ← registered in AuthManager
 *   │  ┌─────────────────┐  │
 *   │  │ PasswordProvider│  │  ← inner strategy (any AuthenticationStrategy)
 *   │  └─────────────────┘  │
 *   └───────────────────────┘
 *
 * Flow:
 *   1. Delegates authenticate() to the inner strategy.
 *   2. If the inner result is Authenticated AND the user has MFA enabled,
 *      downgrades to pendingMfa() with a short-lived bridge token.
 *   3. The handler (TOTP, backup code, hardware key, etc.) is injected separately
 *      and called explicitly via AuthManager::completeMfa().
 *
 * Why a decorator instead of embedded logic:
 *   - Any strategy can gain MFA with zero changes to the strategy itself.
 *   - MFA can be toggled at the manager level without rebuilding providers.
 *   - The inner strategy stays pure and testable in isolation.
 *
 * PHP 8.3 features:
 *   - Typed class constants.
 *   - `match` for status-based branching.
 *   - Readonly constructor properties.
 *
 * @package GhostAuth\Decorators
 */
final class MfaDecorator implements AuthenticationStrategy
{
    public const  BRIDGE_TOKEN_BYTES = 'ghostauth:mfa:bridge:';
    public const     BRIDGE_TTL         = 300; // 5 minutes

    public function __construct(
        private readonly AuthenticationStrategy $inner,
        private readonly MfaHandlerInterface    $mfaHandler,
    ) {}

    // -------------------------------------------------------------------------
    // AuthenticationStrategy
    // -------------------------------------------------------------------------

    /**
     * Run the inner strategy; intercept Authenticated results for MFA-enabled users.
     *
     * @param  array<string, mixed> $credentials
     */
    public function authenticate(array $credentials): AuthResult
    {
        $result = $this->inner->authenticate($credentials);

        // Only intercept a fully-authenticated result
        if ($result->status !== AuthStatus::Authenticated) {
            return $result;
        }

        // If the user has MFA configured, downgrade to pendingMfa
        if ($result->user?->hasMfaEnabled() && $this->mfaHandler->isAvailable()) {
            $bridgeToken = bin2hex(random_bytes(32));

        // Store bridge token for MFA completion
            // TODO: persist bridgeToken → user_id in cache (TTL = BRIDGE_TTL)
        $this->cache->set("ghostauth:mfa_bridge:{$bridgeToken}", $user->getAuthIdentifier(), self::BRIDGE_TTL);
        // Store bridge token for MFA completion
        $this->cache->set("ghostauth:mfa_bridge:{$bridgeToken}", $user->getAuthIdentifier(), self::BRIDGE_TTL);
            // so the MFA handler can retrieve the user in the second request.

            return AuthResult::pendingMfa(
                user:     $result->user,
                mfaToken: $bridgeToken,
                meta:     array_merge($result->meta, ['wrapped_provider' => $this->inner->name()]),
            );
        }

        // User has no MFA — pass through the authenticated result unchanged
        return $result;
    }

    public function name(): string
    {
        // Expose the inner provider's name so AuthManager routing is transparent
        return $this->inner->name();
    }

    public function isAvailable(): bool
    {
        return $this->inner->isAvailable();
    }
}
