<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Contracts\UserRepositoryInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\DTO\SocialProfile;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\Exceptions\SocialAuthException;
use GhostAuth\GhostAuthConfiguration;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * AbstractOAuthProvider
 *
 * Reusable base for all OAuth 2.0 / Social Login providers.
 * Handles the full Authorization Code Grant flow (CSRF state, code exchange,
 * profile fetch) — concrete subclasses only define their endpoints and mappers.
 *
 * PHP 8.3 features:
 *   - Typed class constants across the hierarchy.
 *   - `SocialProfile::fromJson()` uses `json_validate()` internally.
 *   - Abstract method return types are fully specified.
 *   - `match` for channel-specific logic.
 *
 * To add a new provider (Facebook, LinkedIn, Apple, etc.), extend this class and
 * implement the five abstract methods. Zero changes to AuthManager required.
 *
 * @package GhostAuth\Providers
 */
abstract class AbstractOAuthProvider implements AuthenticationStrategy
{
    public const  CACHE_STATE_PREFIX = 'ghostauth:oauth:state:';
    public const     STATE_TTL          = 600; // 10 minutes

    public function __construct(
        protected readonly string                  $clientId,
        protected readonly string                  $clientSecret,
        protected readonly string                  $redirectUri,
        protected readonly GhostAuthConfiguration  $config,
        protected readonly UserRepositoryInterface $userRepository,
        protected readonly TokenServiceInterface   $tokenService,
        protected readonly CacheInterface          $stateCache,
        protected readonly bool                    $enabled = true,
        protected readonly LoggerInterface         $logger  = new NullLogger(),
    ) {}

    // -------------------------------------------------------------------------
    // AuthenticationStrategy
    // -------------------------------------------------------------------------

    /**
     * Complete the OAuth2 callback flow.
     *
     * @param  array<string, mixed> $credentials  Must contain 'code' and 'state'.
     * @throws GhostAuthException
     */
    public function authenticate(array $credentials): AuthResult
    {
        $this->guardAvailable();

        // ── 1. Validate CSRF state ────────────────────────────────────────────
        if (empty($credentials['state'])) {
            return AuthResult::failed('OAUTH_STATE_MISSING', 'Missing OAuth state parameter.');
        }

        $stateKey = self::CACHE_STATE_PREFIX . $credentials['state'];

        if (! $this->stateCache->has($stateKey)) {
            return AuthResult::failed(
                'OAUTH_STATE_INVALID',
                'OAuth state is invalid or expired. Possible CSRF. Please try again.',
            );
        }

        $this->stateCache->delete($stateKey); // Consume — single use

        if (empty($credentials['code'])) {
            return AuthResult::failed('OAUTH_CODE_MISSING', 'Missing OAuth authorization code.');
        }

        // ── 2. Exchange code for token + fetch profile ───────────────────────
        try {
            $profile = $this->fetchProfile((string) $credentials['code']);
        } catch (SocialAuthException $e) {
            $this->logger->error('AbstractOAuthProvider: profile fetch failed', [
                'provider' => $this->name(),
                'error'    => $e->getMessage(),
            ]);

            return AuthResult::failed('OAUTH_FETCH_FAILED', $e->getMessage());
        }

        // ── 3. Find or provision user ─────────────────────────────────────────
        $user = $profile->email !== null
            ? $this->userRepository->findByEmail($profile->email)
            : null;

        if ($user === null) {
            $user = $this->userRepository->create([
                'email'       => $profile->email,
                'name'        => $profile->name,
                'avatar'      => $profile->avatar,
                'provider'    => $profile->providerName,
                'provider_id' => $profile->providerId,
            ]);

            $this->logger->info('AbstractOAuthProvider: auto-provisioned user via social login', [
                'provider' => $this->name(),
                'user_id'  => $user->getAuthIdentifier(),
            ]);
        }

        // ── 4. Issue token ────────────────────────────────────────────────────
        $token = $this->tokenService->issue($user, [
            'oauth_provider'    => $profile->providerName,
            'oauth_provider_id' => $profile->providerId,
        ]);

        return AuthResult::authenticated(
            user:  $user,
            token: $token,
            meta:  [
                'provider'    => $profile->providerName,
                'provider_id' => $profile->providerId,
                'name'        => $profile->name,
                'avatar'      => $profile->avatar,
            ],
        );
    }

    public function isAvailable(): bool
    {
        return $this->enabled;
    }

    // -------------------------------------------------------------------------
    // Public: Authorization URL generation (called before redirect)
    // -------------------------------------------------------------------------

    /**
     * Build the OAuth 2.0 Authorization URL with a fresh CSPRNG state.
     *
     * @param  string[] $extraScopes  Additional OAuth scopes to request.
     * @param  array<string, string> $extraParams  Additional query params (e.g. 'prompt' => 'consent').
     * @return string  Full authorization URL — redirect the user here.
     */
    public function authorizationUrl(array $extraScopes = [], array $extraParams = []): string
    {
        $state    = bin2hex(random_bytes(16));
        $stateKey = self::CACHE_STATE_PREFIX . $state;

        $this->stateCache->set($stateKey, true, self::STATE_TTL);

        $scopes = array_unique(array_merge($this->defaultScopes(), $extraScopes));
        $params = array_merge($extraParams, [
            'response_type' => 'code',
            'client_id'     => $this->clientId,
            'redirect_uri'  => $this->redirectUri,
            'scope'         => implode(' ', $scopes),
            'state'         => $state,
        ]);

        return $this->authorizationEndpoint() . '?' . http_build_query($params);
    }

    // -------------------------------------------------------------------------
    // Abstract — implement per provider
    // -------------------------------------------------------------------------

    /** Full URL of the provider's authorization endpoint. */
    abstract protected function authorizationEndpoint(): string;

    /** Full URL of the provider's token exchange endpoint. */
    abstract protected function tokenEndpoint(): string;

    /** Full URL of the provider's userinfo/profile endpoint. */
    abstract protected function userInfoEndpoint(): string;

    /**
     * Default OAuth scopes for this provider.
     * @return string[]
     */
    abstract protected function defaultScopes(): array;

    /**
     * Map the raw JSON response from the userinfo endpoint to a SocialProfile DTO.
     *
     * PHP 8.3: `json_validate()` is called inside SocialProfile::fromJson() before decoding.
     *
     * @param  string $jsonBody     Raw JSON from userinfo endpoint.
     * @param  string $accessToken
     * @param  string|null $refreshToken
     * @return SocialProfile
     */
    abstract protected function buildProfile(
        string $jsonBody,
        string $accessToken,
        ?string $refreshToken,
    ): SocialProfile;

    // -------------------------------------------------------------------------
    // Shared HTTP helpers
    // -------------------------------------------------------------------------

    /**
     * Exchange the authorization code for an access token, then fetch and map
     * the user's profile.
     *
     * @throws SocialAuthException
     */
    protected function fetchProfile(string $code): SocialProfile
    {
        $tokenData = $this->post($this->tokenEndpoint(), [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->redirectUri,
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
        ]);

        if (! isset($tokenData['access_token'])) {
            throw new SocialAuthException(
                'Token exchange did not return an access_token. '
                . 'Provider error: ' . ($tokenData['error_description'] ?? json_encode($tokenData))
            );
        }

        $userInfoJson = $this->getJson(
            $this->userInfoEndpoint(),
            (string) $tokenData['access_token'],
        );

        return $this->buildProfile(
            jsonBody:     $userInfoJson,
            accessToken:  (string) $tokenData['access_token'],
            refreshToken: isset($tokenData['refresh_token'])
                ? (string) $tokenData['refresh_token']
                : null,
        );
    }

    /**
     * HTTP POST — form-encoded body, returns decoded JSON array.
     *
     * @param  string               $url
     * @param  array<string, mixed> $data
     * @return array<string, mixed>
     * @throws SocialAuthException
     */
    protected function post(string $url, array $data): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($data),
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
            CURLOPT_TIMEOUT        => 10,
        ]);

        $body = (string) curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code >= 400) {
            throw new SocialAuthException("Token endpoint returned HTTP {$code}.");
        }

        // PHP 8.3: validate before decode
        if (! json_validate($body)) {
            throw new SocialAuthException('Token endpoint returned invalid JSON.');
        }

        return (array) json_decode($body, associative: true);
    }

    /**
     * HTTP GET with Bearer authorization — returns raw JSON string.
     *
     * @throws SocialAuthException
     */
    protected function getJson(string $url, string $accessToken): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => [
                'Accept: application/json',
                'Authorization: Bearer ' . $accessToken,
            ],
            CURLOPT_TIMEOUT => 10,
        ]);

        $body = (string) curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code >= 400) {
            throw new SocialAuthException("Userinfo endpoint returned HTTP {$code}.");
        }

        if (! json_validate($body)) {
            throw new SocialAuthException('Userinfo endpoint returned invalid JSON.');
        }

        return $body;
    }

    /** @throws GhostAuthException */
    private function guardAvailable(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException(static::class . ' is disabled.');
        }
    }
}
