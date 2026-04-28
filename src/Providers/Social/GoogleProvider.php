<?php

declare(strict_types=1);

namespace GhostAuth\Providers\Social;

use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\DTO\SocialProfile;
use GhostAuth\Providers\AbstractOAuthProvider;

/**
 * GoogleProvider
 *
 * OAuth 2.0 / OIDC provider for Google Sign-In.
 * Only the Google-specific endpoints, scopes, and field mapping live here.
 *
 * @package GhostAuth\Providers\Social
 */
final class GoogleProvider extends AbstractOAuthProvider
{
    public const  AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
    public const  TOKEN_ENDPOINT         = 'https://oauth2.googleapis.com/token';
    public const  USERINFO_ENDPOINT      = 'https://www.googleapis.com/oauth2/v3/userinfo';

    public function name(): string
    {
        return AuthenticationStrategy::PROVIDER_GOOGLE;
    }

    protected function authorizationEndpoint(): string
    {
        return self::AUTHORIZATION_ENDPOINT;
    }

    protected function tokenEndpoint(): string
    {
        return self::TOKEN_ENDPOINT;
    }

    protected function userInfoEndpoint(): string
    {
        return self::USERINFO_ENDPOINT;
    }

    protected function defaultScopes(): array
    {
        return ['openid', 'email', 'profile'];
    }

    /**
     * Map Google userinfo JSON to SocialProfile.
     * Google fields: sub, email, name, picture, email_verified
     */
    protected function buildProfile(string $jsonBody, string $accessToken, ?string $refreshToken): SocialProfile
    {
        return SocialProfile::fromJson(
            json:         $jsonBody,
            providerName: $this->name(),
            accessToken:  $accessToken,
            refreshToken: $refreshToken,
            mapper:       static fn (array $raw) => [
                'id'     => $raw['sub']     ?? '',
                'name'   => $raw['name']    ?? null,
                'email'  => $raw['email']   ?? null,
                'avatar' => $raw['picture'] ?? null,
            ],
        );
    }
}
