<?php

declare(strict_types=1);

namespace GhostAuth\Mfa;

/**
 * TotpAuthenticator (v2)
 *
 * RFC 6238 TOTP — fully readonly, typed-constant, PHP 8.3.
 *
 * @package GhostAuth\Mfa
 */
readonly class TotpAuthenticator
{
    public const DEFAULT_DIGITS = 6;
    public const DEFAULT_PERIOD = 30;
    public const DEFAULT_ALGO   = 'sha1';

    public const ALGO_SHA1   = 'sha1';
    public const ALGO_SHA256 = 'sha256';
    public const ALGO_SHA512 = 'sha512';

    /**
     * Generate a cryptographically random TOTP secret.
     *
     * @param  int    $bytes  Raw entropy (20 → 160 bits → 32 base32 chars).
     * @return string         Base32-encoded, uppercase, no padding.
     */
    public static function generateSecret(int $bytes = 20): string
    {
        return self::base32Encode(random_bytes($bytes));
    }

    /** Generate the current TOTP code. */
    public static function generate(
        string $base32Secret,
        int $digits = self::DEFAULT_DIGITS,
        int $period = self::DEFAULT_PERIOD,
        ?int $timestamp = null,
        string $algo = self::DEFAULT_ALGO,
    ): string {
        return self::hotp(
            $base32Secret,
            intdiv($timestamp ?? time(), $period),
            $digits,
            $algo,
        );
    }

    /**
     * Verify a TOTP code with clock skew tolerance.
     * Checks [current - leeway, ..., current + leeway].
     */
    public static function verify(
        string $base32Secret,
        string $code,
        int $digits = self::DEFAULT_DIGITS,
        int $period = self::DEFAULT_PERIOD,
        int $leeway = 1,
        ?int $timestamp = null,
        string $algo = self::DEFAULT_ALGO,
    ): bool {
        $now = $timestamp ?? time();
        $padded = str_pad($code, $digits, '0', STR_PAD_LEFT);

        for ($i = -$leeway; $i <= $leeway; $i++) {
            if (hash_equals(
                self::generate($base32Secret, $digits, $period, $now + $i * $period, $algo),
                $padded,
            )) {
                return true;
            }
        }

        return false;
    }

    /** Generate otpauth:// provisioning URI for QR code. */
    public static function provisioningUri(
        string $base32Secret,
        string $accountName,
        string $issuer,
        int $digits = self::DEFAULT_DIGITS,
        int $period = self::DEFAULT_PERIOD,
        string $algo = self::DEFAULT_ALGO,
    ): string {
        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d',
            rawurlencode($issuer . ':' . $accountName),
            $base32Secret,
            rawurlencode($issuer),
            strtoupper($algo),
            $digits,
            $period,
        );
    }

    /** Generate N single-use backup codes (32-bit hex each). */
    public static function generateBackupCodes(int $count = 8): array
    {
        return array_map(fn() => bin2hex(random_bytes(4)), range(1, $count));
    }

    /** Hash backup codes for storage. */
    public static function hashBackupCodes(array $codes): array
    {
        return array_map(
            fn($code) => password_hash($code, PASSWORD_ARGON2ID, [
                'memory_cost' => 16384,
                'time_cost'   => 2,
                'threads'     => 1,
            ]),
            $codes,
        );
    }

    /** Verify + return matched code. Caller must remove the matched hash after use. */
    public static function verifyBackupCode(string $code, array $hashedCodes): ?string
    {
        foreach ($hashedCodes as $hashed) {
            if (password_verify($code, $hashed)) {
                return $code;
            }
        }
        return null;
    }

    // =========================================================================
    // Private
    // =========================================================================

    private static function hotp(string $secret, int $counter, int $digits, string $algo): string
    {
        $hmac = hash_hmac($algo, pack('J', $counter), self::base32Decode($secret), binary: true);
        $offset = ord($hmac[19]) & 0x0F;

        $binCode = (
            ((ord($hmac[$offset]) & 0x7F) << 24) |
            ((ord($hmac[$offset + 1]) & 0xFF) << 16) |
            ((ord($hmac[$offset + 2]) & 0xFF) << 8) |
            (ord($hmac[$offset + 3]) & 0xFF)
        );

        return str_pad((string) ($binCode % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    private static function base32Encode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $result = ''; $buffer = 0; $bits = 0;

        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $buffer = ($buffer << 8) | ord($data[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $result .= $alphabet[($buffer >> $bits) & 0x1F];
            }
        }
        if ($bits > 0) {
            $result .= $alphabet[($buffer << (5 - $bits)) & 0x1F];
        }

        return $result;
    }

    private static function base32Decode(string $data): string
    {
        $data = strtoupper(trim($data, '='));
        $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
        $result = ''; $buffer = 0; $bits = 0;

        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $buffer = ($buffer << 5) | $map[$data[$i]];
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $result .= chr(($buffer >> $bits) & 0xFF);
            }
        }

        return $result;
    }
}
