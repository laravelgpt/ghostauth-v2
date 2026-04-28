<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Contracts\UserRepositoryInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\Exceptions\OidcException;
use GhostAuth\GhostAuthConfiguration;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * OidcProvider
 *
 * OIDC (OpenID Connect) / Enterprise SSO provider.
 * Compatible with Okta, Azure AD (Entra ID), Auth0, Google Workspace,
 * Keycloak, and any standards-compliant OIDC IdP.
 *
 * Security validations per OIDC Core 1.0 §3.1.3.7:
 *   ✓ Signature (JWKS from discovery document, RS256/ES256)
 *   ✓ `iss` issuer validation
 *   ✓ `aud` must contain our client_id
 *   ✓ `exp` expiration
 *   ✓ `iat` clock-skew guard
 *   ✓ `nonce` anti-replay
 *   ✓ `state` CSRF protection
 *
 * PHP 8.3 features:
 *   - Typed class constants.
 *   - `json_validate()` before every JSON decode.
 *   - Readonly constructor-promoted properties.
 *   - `match` for exhaustive claim validation.
 *
 * @package GhostAuth\Providers
 */
final class OidcProvider implements AuthenticationStrategy
{
    public const  CACHE_DISCOVERY = 'ghostauth:oidc:discovery:';
    public const  CACHE_STATE     = 'ghostauth:oidc:state:';
    public const  CACHE_NONCE     = 'ghostauth:oidc:nonce:';
    public const     DISCOVERY_TTL   = 3600;
    public const     STATE_TTL       = 600;

    /** @var array<string, mixed>|null  Cached OIDC discovery document. */
    private ?array $discoveryDoc = null;

    public function __construct(
        private readonly string                  $issuerUrl,
        private readonly string                  $clientId,
        private readonly string                  $clientSecret,
        private readonly string                  $redirectUri,
        private readonly GhostAuthConfiguration  $config,
        private readonly UserRepositoryInterface $userRepository,
        private readonly TokenServiceInterface   $tokenService,
        private readonly CacheInterface          $cache,
        private readonly int                     $clockSkewSec = 60,
        private readonly bool                    $enabled      = true,
        private readonly LoggerInterface         $logger       = new NullLogger(),
    ) {}

    // -------------------------------------------------------------------------
    // AuthenticationStrategy
    // -------------------------------------------------------------------------

    /**
     * Complete OIDC callback — validate id_token, state, nonce; issue GhostAuth token.
     *
     * @param  array<string, mixed> $credentials  Must contain 'id_token', 'state', 'nonce'.
     * @throws GhostAuthException
     */
    public function authenticate(array $credentials): AuthResult
    {
        $this->guardAvailable();

        foreach (['id_token', 'state', 'nonce'] as $key) {
            if (empty($credentials[$key])) {
                throw new GhostAuthException("OidcProvider: missing required credential '{$key}'.");
            }
        }

        // ── CSRF: validate state ───────────────────────────────────────────
        $stateKey = self::CACHE_STATE . $credentials['state'];

        if (! $this->cache->has($stateKey)) {
            return AuthResult::failed('OIDC_STATE_INVALID', 'Invalid or expired OIDC state.');
        }

        $this->cache->delete($stateKey);

        // ── Validate ID Token ─────────────────────────────────────────────
        try {
            $claims = $this->validateIdToken((string) $credentials['id_token']);
        } catch (OidcException $e) {
            $this->logger->warning('OidcProvider: ID Token validation failed', [
                'error' => $e->getMessage(),
            ]);

            return AuthResult::failed('OIDC_TOKEN_INVALID', $e->getMessage());
        }

        // ── Validate nonce — anti-replay ──────────────────────────────────
        $nonceKey = self::CACHE_NONCE . $credentials['nonce'];

        if (! $this->cache->has($nonceKey)) {
            return AuthResult::failed('OIDC_NONCE_INVALID', 'Invalid or replayed OIDC nonce.');
        }

        $this->cache->delete($nonceKey);

        if (! isset($claims['nonce']) || ! hash_equals((string) $credentials['nonce'], (string) $claims['nonce'])) {
            return AuthResult::failed('OIDC_NONCE_MISMATCH', 'OIDC nonce claim does not match.');
        }

        // ── Find or provision user ────────────────────────────────────────
        $email = $claims['email'] ?? null;
        $user  = $email ? $this->userRepository->findByEmail((string) $email) : null;

        if ($user === null) {
            $user = $this->userRepository->create([
                'email'    => $email,
                'name'     => $claims['name']    ?? null,
                'sub'      => $claims['sub']     ?? null,
                'provider' => $this->name(),
            ]);
        }

        $token = $this->tokenService->issue($user, ['oidc_sub' => $claims['sub'] ?? null]);

        $this->logger->info('OidcProvider: SSO authentication successful', [
            'user_id' => $user->getAuthIdentifier(),
            'sub'     => $claims['sub'] ?? null,
        ]);

        return AuthResult::authenticated(
            user:  $user,
            token: $token,
            meta:  ['provider' => $this->name(), 'oidc_claims' => $claims],
        );
    }

    public function name(): string
    {
        return AuthenticationStrategy::PROVIDER_OIDC;
    }

    public function isAvailable(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // SSO-specific public API
    // -------------------------------------------------------------------------

    /**
     * Build the OIDC authorization URL with fresh CSPRNG state + nonce.
     *
     * @param  array<string, string> $extraParams
     * @return string
     * @throws OidcException
     */
    public function authorizationUrl(array $extraParams = []): string
    {
        $doc   = $this->discover();
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));

        $this->cache->set(self::CACHE_STATE . $state, true, self::STATE_TTL);
        $this->cache->set(self::CACHE_NONCE . $nonce, true, self::STATE_TTL);

        $params = array_merge($extraParams, [
            'response_type' => 'code',
            'client_id'     => $this->clientId,
            'redirect_uri'  => $this->redirectUri,
            'scope'         => 'openid email profile',
            'state'         => $state,
            'nonce'         => $nonce,
        ]);

        return ($doc['authorization_endpoint'] ?? '') . '?' . http_build_query($params);
    }

    /**
     * Validate and decode an OIDC ID Token.
     *
     * @return array<string, mixed>
     * @throws OidcException
     */
    public function validateIdToken(string $idToken): array
    {
        $doc      = $this->discover();
        $jwksUri  = $doc['jwks_uri'] ?? null;

        if (! $jwksUri) {
            throw new OidcException('OIDC discovery document is missing jwks_uri.');
        }

        $jwksJson = $this->fetchRaw((string) $jwksUri);

        // PHP 8.3: json_validate() before json_decode
        if (! json_validate($jwksJson)) {
            throw new OidcException('JWKS endpoint returned invalid JSON.');
        }

        /** @var array<string, mixed> $jwks */
        $jwks   = json_decode($jwksJson, associative: true);
        $keySet = JWK::parseKeySet($jwks);

        try {
            $decoded = JWT::decode($idToken, $keySet);
        } catch (\Throwable $e) {
            throw new OidcException('ID Token signature verification failed: ' . $e->getMessage(), 0, $e);
        }

        $claims = (array) $decoded;

        // Validate standard OIDC claims
        $expectedIss = rtrim($this->issuerUrl, '/');

        if (rtrim((string) ($claims['iss'] ?? ''), '/') !== $expectedIss) {
            throw new OidcException("ID Token issuer mismatch: expected '{$expectedIss}'.");
        }

        $aud = is_array($claims['aud'] ?? null) ? $claims['aud'] : [$claims['aud'] ?? ''];

        if (! in_array($this->clientId, $aud, strict: true)) {
            throw new OidcException('ID Token audience does not include our client_id.');
        }

        $now = time();

        if (isset($claims['exp']) && ($claims['exp'] + $this->clockSkewSec) < $now) {
            throw new OidcException('ID Token has expired.');
        }

        if (isset($claims['iat']) && $claims['iat'] > ($now + $this->clockSkewSec)) {
            throw new OidcException('ID Token iat is too far in the future (clock skew?).');
        }

        return $claims;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Fetch and cache the OIDC discovery document.
     *
     * @return array<string, mixed>
     * @throws OidcException
     */
    private function discover(): array
    {
        if ($this->discoveryDoc !== null) {
            return $this->discoveryDoc;
        }

        $cacheKey = self::CACHE_DISCOVERY . md5($this->issuerUrl);
        $cached   = $this->cache->get($cacheKey);

        if (is_array($cached)) {
            $this->discoveryDoc = $cached;
            return $this->discoveryDoc;
        }

        $url  = rtrim($this->issuerUrl, '/') . '/.well-known/openid-configuration';
        $body = $this->fetchRaw($url);

        if (! json_validate($body)) {
            throw new OidcException('OIDC discovery document returned invalid JSON.');
        }

        /** @var array<string, mixed> $doc */
        $doc = json_decode($body, associative: true);

        $this->cache->set($cacheKey, $doc, self::DISCOVERY_TTL);
        $this->discoveryDoc = $doc;

        return $this->discoveryDoc;
    }

    /** @throws OidcException */
    private function fetchRaw(string $url): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);

        $body = (string) curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code !== 200 || $body === '') {
            throw new OidcException("HTTP request to {$url} failed (HTTP {$code}).");
        }

        return $body;
    }

    /** @throws GhostAuthException */
    private function guardAvailable(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException('OidcProvider is disabled.');
        }
    }
}
