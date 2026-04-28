<?php

declare(strict_types=1);

namespace GhostAuth\Auth;

/**
 * Role
 *
 * Role-Based Access Control (RBAC) role definition.
 * Roles can be assigned to users and contain permissions.
 *
 * Example roles: 'admin', 'moderator', 'editor', 'user', 'guest'
 *
 * @package GhostAuth\Auth
 */
final class Role
{
    public function __construct(
        private readonly string $name,        // e.g. 'admin', 'moderator'
        private readonly string $displayName, // Human readable: 'Administrator'
        private readonly string $description, // Description of what role can do
        private readonly array  $permissions = [], // Permission names
        private readonly int    $priority = 0,   // Higher priority roles win conflicts
        private readonly bool   $system = false, // System roles can't be deleted
    ) {}

    public function getName(): string
    {
        return $this->name;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getPermissions(): array
    {
        return $this->permissions;
    }

    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }

    public function addPermission(string $permission): static
    {
        if (! in_array($permission, $this->permissions, true)) {
            $this->permissions[] = $permission;
        }
        return $this;
    }

    public function removePermission(string $permission): static
    {
        $this->permissions = array_filter(
            $this->permissions,
            fn($p) => $p !== $permission
        );
        return $this;
    }

    public function getPriority(): int
    {
        return $this->priority;
    }

    public function isSystem(): bool
    {
        return $this->system;
    }

    public function equals(Role $other): bool
    {
        return $this->name === $other->name;
    }

    public static function admin(): static
    {
        return new static(
            name:        'admin',
            displayName: 'Administrator',
            description: 'Full system access',
            permissions: ['*'], // Wildcard means all permissions
            priority:    1000,
            system:      true,
        );
    }

    public static function user(): static
    {
        return new static(
            name:        'user',
            displayName: 'User',
            description: 'Regular authenticated user',
            permissions: [
                'profile.read',
                'profile.update',
                'logout',
            ],
            priority:    0,
        );
    }

    public static function guest(): static
    {
        return new static(
            name:        'guest',
            displayName: 'Guest',
            description: 'Unauthenticated visitor',
            permissions: [
                'content.read',
            ],
            priority:    -1000,
        );
    }
}
