<?php

declare(strict_types=1);

namespace GhostAuth\Contracts;

/**
 * UserRepositoryInterface
 *
 * Bridges GhostAuth with the application's persistence layer.
 * GhostAuth has zero opinions about databases or ORMs.
 *
 * @package GhostAuth\Contracts
 */
interface UserRepositoryInterface
{
    public function findByEmail(string $email): ?AuthenticatableInterface;
    public function findByPhone(string $phone): ?AuthenticatableInterface;
    public function findById(int|string $id): ?AuthenticatableInterface;

    /**
     * @param  array<string, mixed> $attributes
     */
    public function create(array $attributes): AuthenticatableInterface;

    /**
     * @param  array<string, mixed> $attributes
     */
    public function update(int|string $id, array $attributes): bool;
}
