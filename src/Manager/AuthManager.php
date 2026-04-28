<?php

declare(strict_types=1);

namespace GhostAuth\Manager;

use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Enums\AuthStatus;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\GhostAuthConfiguration;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * AuthManager
 *
 * The central engine of GhostAuth. Acts as a Strategy registry and
 * dispatcher — holds named authentication strategies and routes
 * authenticate() calls to the correct one.
 *
 * Design principles:
 *   - Framework-agnostic (no DI container dependency).
 *   - Easily wired via any PSR-11 container.
 *   - Fluent registration API for readable boot code.
 *   - All provider dispatch goes through the same path — consistent
 *     logging, timing, and error handling regardless of strategy.
 *
 * PHP 8.3 features:
 *   - Typed class constants (`public const string`, `public const int`).
 *   - `readonly` constructor-promoted properties.
 *   - `never` return type on guard methods.
 *   - `match` for clean, exhaustive branching.
 *   - Named arguments throughout for readability.
 *
 * @package GhostAuth\Manager
 */
final class AuthManager
{
    // -------------------------------------------------------------------------
    // PHP 8.3: Typed class constants
    // -------------------------------------------------------------------------

    public const  VERSION     = GhostAuthConfiguration::VERSION;
    public const     MAX_RETRIES = 3;

    /**
     * Registered strategies keyed by their name().
     *
     * @var array<string, AuthenticationStrategy>
     */
    private array $strategies = [];

    /** The default strategy name used when authenticate() is called without one. */
    private ?string $defaultStrategy = null;

    public function __construct(
        private readonly GhostAuthConfiguration $config,
        private readonly TokenServiceInterface  $tokenService,
        private readonly LoggerInterface        $logger = new NullLogger(),
    ) {
        $this->logger->debug('AuthManager booted', [
            'version'      => self::VERSION,
            'token_driver' => $this->config->tokenDriver->value,
            'mfa_enabled'  => $this->config->mfaEnabled,
        ]);
    }

    // -------------------------------------------------------------------------
    // Strategy registry — fluent builder API
    // -------------------------------------------------------------------------

    /**
     * Register an authentication strategy.
     *
     * @param  AuthenticationStrategy $strategy    The provider/decorator to register.
     * @param  bool                   $setDefault  Set as the default when no provider is specified.
     * @return static  Fluent — allows chaining.
     */
    public function register(AuthenticationStrategy $strategy, bool $setDefault = false): static
    {
        $name = $strategy->name();

        $this->strategies[$name] = $strategy;

        if ($setDefault || $this->defaultStrategy === null) {
            $this->defaultStrategy = $name;
        }

        $this->logger->debug("AuthManager: registered strategy '{$name}'", [
            'available' => $strategy->isAvailable(),
            'default'   => $this->defaultStrategy === $name,
        ]);

        return $this;
    }

    /**
     * Retrieve a registered strategy by name.
     *
     * @throws GhostAuthException  If no strategy is registered under that name.
     */
    public function strategy(string $name): AuthenticationStrategy
    {
        return $this->strategies[$name]
            ?? throw new GhostAuthException(
                "AuthManager: no strategy registered with name '{$name}'. "
                . "Registered: [" . implode(', ', array_keys($this->strategies)) . ']'
            );
    }

    /**
     * Return all registered strategies.
     *
     * @return array<string, AuthenticationStrategy>
     */
    public function all(): array
    {
        return $this->strategies;
    }

    // -------------------------------------------------------------------------
    // Core dispatch
    // -------------------------------------------------------------------------

    /**
     * Authenticate using the named strategy (or the default strategy if null).
     *
     * @param  array<string, mixed> $credentials  Strategy-specific credential map.
     * @param  string|null          $provider     Strategy name, or null for the default.
     * @return AuthResult                         Immutable result — inspect $result->status.
     *
     * @throws GhostAuthException  On misconfiguration or infrastructure error.
     */
    public function authenticate(array $credentials, ?string $provider = null): AuthResult
    {
        $providerName = $provider ?? $this->defaultStrategy;

        if ($providerName === null) {
            throw new GhostAuthException(
                'AuthManager: no provider specified and no default strategy is configured.'
            );
        }

        $strategy = $this->strategy($providerName);

        if (! $strategy->isAvailable()) {
            $this->logger->error("AuthManager: strategy '{$providerName}' is unavailable.");

            return AuthResult::failed(
                errorCode:    'PROVIDER_UNAVAILABLE',
                errorMessage: "The '{$providerName}' authentication method is currently unavailable.",
            );
        }

        $start = hrtime(as_num: true);

        $this->logger->info("AuthManager: dispatching → '{$providerName}'");

        $result = $strategy->authenticate($credentials);

        $elapsed = round((hrtime(as_num: true) - $start) / 1_000_000, 2);

        // Structured log — same shape regardless of strategy or outcome
        $this->logger->log(
            level:   $result->isFailed() ? 'warning' : 'info',
            message: "AuthManager: '{$providerName}' → {$result->status->value}",
            context: array_merge($result->toLogContext(), ['provider' => $providerName, 'total_ms' => $elapsed]),
        );

        return $result;
    }

    // -------------------------------------------------------------------------
    // Token operations (convenience delegation)
    // -------------------------------------------------------------------------

    /**
     * Verify a previously issued token.
     *
     * @return array<string, mixed>  Decoded payload.
     * @throws \GhostAuth\Exceptions\TokenException  On invalid/expired/revoked token.
     */
    public function verifyToken(string $token): array
    {
        return $this->tokenService->verify($token);
    }

    /**
     * Revoke a token (logout).
     * Adds the token's jti to the denylist cache if configured.
     */
    public function revokeToken(string $token): bool
    {
        $revoked = $this->tokenService->revoke($token);

        $this->logger->info('AuthManager: token revocation', ['success' => $revoked]);

        return $revoked;
    }

    // -------------------------------------------------------------------------
    // Introspection
    // -------------------------------------------------------------------------

    /** Return the AuthManager configuration snapshot for debugging. */
    public function inspect(): array
    {
        return [
            'version'          => self::VERSION,
            'default_strategy' => $this->defaultStrategy,
            'strategies'       => array_map(
                fn (AuthenticationStrategy $s) => [
                    'name'      => $s->name(),
                    'available' => $s->isAvailable(),
                    'class'     => $s::class,
                ],
                $this->strategies,
            ),
            'config' => [
                'app_name'      => $this->config->appName,
                'jwt_algorithm' => $this->config->jwtAlgorithm,
                'jwt_ttl'       => $this->config->jwtTtlSeconds,
                'token_driver'  => $this->config->tokenDriver->value,
                'mfa_enabled'   => $this->config->mfaEnabled,
                'auto_provision'=> $this->config->autoProvision,
            ],
        ];
    }
}
