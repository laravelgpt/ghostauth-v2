<?php

declare(strict_types=1);

namespace GhostAuth\Auth;

/**
 * Permission
 *
 * Individual permission in an RBAC system.
 * Permissions represent specific actions users can perform.
 *
 * Format: resource.action (e.g. 'user.delete', 'post.create')
 * Wildcards supported: 'user.*' means all user actions
 *
 * @package GhostAuth\Auth
 */
final class Permission
{
    public function __construct(
        private readonly string $name,        // e.g. 'user.create', 'post.delete'
        private readonly string $displayName, // Human readable: 'Create User'
        private readonly string $description, // What this permission allows
        private readonly string $resource,    // e.g. 'user', 'post', 'settings'
        private readonly string $action,      // e.g. 'create', 'delete', 'view'
        private readonly bool   $system = false, // System permissions can't be deleted
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

    public function getResource(): string
    {
        return $this->resource;
    }

    public function getAction(): string
    {
        return $this->action;
    }

    public function isSystem(): bool
    {
        return $this->system;
    }

    /**
     * Check if this permission matches another permission or wildcard.
     *
     * @param  string $permission  Permission to check against (e.g. 'user.*')
     * @return bool                True if this permission matches the given pattern
     */
    public function matches(string $permission): bool
    {
        // Exact match
        if ($this->name === $permission) {
            return true;
        }

        // Wildcard match (e.g. 'user.*' matches 'user.create')
        if (str_ends_with($permission, '.*')) {
            $prefix = substr($permission, 0, -2); // Remove '.*'
            return str_starts_with($this->name, $prefix . '.');
        }

        return false;
    }

    /**
     * Check if this permission implies another (more specific) permission.
     * e.g. 'user.*' implies 'user.create'
     *
     * @param  string $permission  The permission to check if implied
     * @return bool                True if this permission implies the given one
     */
    public function implies(string $permission): bool
    {
        return $this->matches($permission);
    }

    /**
     * Parse a permission string into resource and action.
     *
     * @param  string $permission  Permission string like 'user.create'
     * @return array{resource: string, action: string}
     */
    public static function parse(string $permission): array
    {
        $parts = explode('.', $permission, 2);
        $resource = $parts[0] ?? '';
        $action   = $parts[1] ?? '';

        return [
            'resource' => $resource,
            'action'   => $action,
        ];
    }

    /**
     * Create a permission from resource and action.
     *
     * @param  string $resource  Resource name (e.g. 'user')
     * @param  string $action    Action name (e.g. 'create')
     * @return static
     */
    public static function fromResourceAction(string $resource, string $action): static
    {
        return new static(
            name:        "$resource.$action",
            displayName: ucfirst($action) . ' ' . ucfirst($resource),
            description: "Permission to $action a $resource",
            resource:    $resource,
            action:      $action,
        );
    }

    /**
     * Get all possible actions for a resource (convention-based).
     *
     * @param  string $resource  Resource name
     * @return string[]          Common actions: create, read, update, delete, list, export, import
     */
    public static function standardActions(string $resource): array
    {
        return [
            "$resource.create",
            "$resource.read",
            "$resource.update",
            "$resource.delete",
            "$resource.list",
            "$resource.export",
            "$resource.import",
            "$resource.view",   // Alias for read
            "$resource.edit",   // Alias for update
            "$resource.remove", // Alias for delete
        ];
    }
}
