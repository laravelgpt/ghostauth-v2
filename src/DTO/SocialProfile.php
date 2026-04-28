<?php

declare(strict_types=1);

namespace GhostAuth\DTO;

/**
 * SocialProfile
 *
 * Readonly DTO representing a normalized user profile retrieved from any
 * OAuth 2.0 / Social provider (Google, GitHub, Facebook, etc.).
 *
 * PHP 8.3: `readonly class` with typed properties and a JSON-based factory.
 *
 * @package GhostAuth\DTO
 */
readonly class SocialProfile
{
    /**
     * @param string      $providerId    Provider-scoped unique user ID (e.g. Google `sub`).
     * @param string      $providerName  Normalized provider name ('google', 'github', etc.).
     * @param string|null $name          Display name (may be null for some providers).
     * @param string|null $email         Primary email address.
     * @param string|null $avatar        Profile picture URL.
     * @param string      $accessToken   OAuth access token for calling provider APIs.
     * @param string|null $refreshToken  OAuth refresh token (provider-dependent).
     * @param array<string, mixed> $raw  Raw profile payload for provider-specific access.
     */
    public function __construct(
        public readonly string  $providerId,
        public readonly string  $providerName,
        public readonly ?string $name,
        public readonly ?string $email,
        public readonly ?string $avatar,
        public readonly string  $accessToken,
        public readonly ?string $refreshToken,
        public readonly array   $raw,
    ) {}

    /**
     * Build a SocialProfile from a raw JSON string (e.g. social provider webhook payload).
     *
     * PHP 8.3: uses `json_validate()` before `json_decode()` to fail fast
     * without the overhead of a full decode on malformed payloads.
     *
     * @param  string               $json          Raw JSON from provider userinfo endpoint.
     * @param  string               $providerName  Normalized provider name.
     * @param  string               $accessToken   The OAuth access token.
     * @param  string|null          $refreshToken  Optional refresh token.
     * @param  callable(array): array $mapper       Maps raw array → normalized field array.
     * @return static
     *
     * @throws \GhostAuth\Exceptions\SocialAuthException  On invalid JSON.
     */
    public static function fromJson(
        string $json,
        string $providerName,
        string $accessToken,
        ?string $refreshToken,
        callable $mapper,
    ): static {
        // PHP 8.3: json_validate() is significantly faster than decode+check
        // for validation-only paths — avoids allocating the decoded structure.
        if (! json_validate($json)) {
            throw new \GhostAuth\Exceptions\SocialAuthException(
                "Invalid JSON received from {$providerName} userinfo endpoint."
            );
        }

        /** @var array<string, mixed> $raw */
        $raw        = json_decode($json, associative: true);
        $normalized = $mapper($raw);

        return new static(
            providerId:   (string) ($normalized['id']      ?? ''),
            providerName: $providerName,
            name:         $normalized['name']               ?? null,
            email:        $normalized['email']              ?? null,
            avatar:       $normalized['avatar']             ?? null,
            accessToken:  $accessToken,
            refreshToken: $refreshToken,
            raw:          $raw,
        );
    }
}
