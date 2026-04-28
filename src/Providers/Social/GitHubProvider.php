<?php

declare(strict_types=1);

namespace GhostAuth\Providers\Social;

use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\DTO\SocialProfile;
use GhostAuth\Providers\AbstractOAuthProvider;

/**
 * GitHubProvider
 *
 * OAuth 2.0 provider for GitHub Login.
 *
 * @package GhostAuth\Providers\Social
 */
final class GitHubProvider extends AbstractOAuthProvider
{
    public const  AUTHORIZATION_ENDPOINT = 'https://github.com/login/oauth/authorize';
    public const  TOKEN_ENDPOINT         = 'https://github.com/login/oauth/access_token';
    public const  USERINFO_ENDPOINT      = 'https://api.github.com/user';

    public function name(): string
    {
        return AuthenticationStrategy::PROVIDER_GITHUB;
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
        return ['read:user', 'user:email'];
    }

    /**
     * Map GitHub /user JSON to SocialProfile.
     * GitHub fields: id, login, name, email, avatar_url
     */
    protected function buildProfile(string $jsonBody, string $accessToken, ?string $refreshToken): SocialProfile
    {
        return SocialProfile::fromJson(
            json:         $jsonBody,
            providerName: $this->name(),
            accessToken:  $accessToken,
            refreshToken: $refreshToken, // GitHub does not issue refresh tokens
            mapper:       static fn (array $raw) => [
                'id'     => (string) ($raw['id']         ?? ''),
                'name'   => $raw['name']   ?? $raw['login'] ?? null,
                'email'  => $raw['email']  ?? null,
                'avatar' => $raw['avatar_url'] ?? null,
            ],
        );
    }
}
