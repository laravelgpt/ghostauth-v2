<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * AuthenticatableInterface
 *
 * The only shape of a user entity that GhostAuth will ever interact with.
 * Keeps GhostAuth completely decoupled from any ORM, framework, or data layer.
 *
 * @package GhostAuth\Contracts
 */
interface AuthenticatableInterface
{
    /** Unique identifier embedded as the JWT `sub` claim. */
    public function getAuthIdentifier(): int|string;

    /** Name of the identifier attribute ('id', 'uuid', etc.). */
    public function getAuthIdentifierName(): string;

    /** Argon2id/bcrypt hash. Return null for passwordless-only accounts. */
    public function getAuthPassword(): ?string;

    /** Primary email address. */
    public function getEmail(): ?string;

    /** E.164-formatted phone number. */
    public function getPhone(): ?string;

    /**
     * Whether the user has MFA configured.
     * Used by the MFA decorator to determine whether a second factor is required.
     */
    public function hasMfaEnabled(): bool;

    /**
     * Extra claims to embed in the JWT payload.
     * @return array<string, mixed>
     */
    public function getJwtClaims(): array;
}
