<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * TokenServiceInterface
 *
 * Abstracts token issuance, verification, and revocation so providers
 * are decoupled from the underlying mechanism (JWT vs. session token).
 *
 * @package GhostAuth\Contracts
 */
interface TokenServiceInterface
{
    /**
     * @param  array<string, mixed> $extraClaims
     * @throws \GhostAuth\Exceptions\TokenException
     */
    public function issue(AuthenticatableInterface $user, array $extraClaims = []): string;

    /**
     * @return array<string, mixed>
     * @throws \GhostAuth\Exceptions\TokenException
     */
    public function verify(string $token): array;

    /** @throws \GhostAuth\Exceptions\TokenException */
    public function revoke(string $token): bool;
}
