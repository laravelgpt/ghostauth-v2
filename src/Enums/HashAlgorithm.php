<?php

declare(strict_types=1);

namespace GhostAuth\Enums;

/**
 * HashAlgorithm
 *
 * Backed enum representing the supported password hashing algorithms.
 * Argon2id is the strongly recommended default per OWASP 2023+.
 *
 * PHP 8.3: backed enums with typed cases allow clean, exhaustive matching.
 *
 * @package GhostAuth\Enums
 */
enum HashAlgorithm: string
{
    /** Argon2id — memory-hard, GPU/ASIC resistant. Default. */
    case Argon2id = 'argon2id';

    /** Bcrypt — widely supported but not memory-hard. Legacy compat only. */
    case Bcrypt = 'bcrypt';

    /**
     * Return the PHP PASSWORD_* constant for use with password_hash().
     *
     * @return int|string
     */
    public function toPhpConstant(): int|string
    {
        return match ($this) {
            self::Argon2id => PASSWORD_ARGON2ID,
            self::Bcrypt   => PASSWORD_BCRYPT,
        };
    }

    /**
     * Human-readable label.
     */
    public function label(): string
    {
        return match ($this) {
            self::Argon2id => 'Argon2id (recommended)',
            self::Bcrypt   => 'Bcrypt (legacy)',
        };
    }
}
