<?php

declare(strict_types=1);

namespace GhostAuth;

use GhostAuth\Enums\HashAlgorithm;
use GhostAuth\Enums\TokenDriver;
use GhostAuth\Exceptions\ConfigurationException;

/**
 * GhostAuthConfiguration
 *
 * An immutable, readonly configuration value object for the entire GhostAuth package.
 *
 * PHP 8.3 features used:
 *   - `readonly class` — all properties are immutable after construction.
 *   - Typed class constants (`public const string`, `public const int`).
 *   - Constructor property promotion with full type coverage.
 *
 * The configuration object is intentionally created once (at boot) and shared
 * across all providers via the DI container. It cannot be mutated after creation,
 * eliminating a whole class of runtime misconfiguration bugs.
 *
 * Usage:
 *   $config = GhostAuthConfiguration::fromArray([
 *       'app_name'   => 'MyApp',
 *       'jwt_secret' => 'your-secret',
 *       ...
 *   ]);
 *
 * @package GhostAuth
 */
readonly class GhostAuthConfiguration
{
    // -------------------------------------------------------------------------
    // PHP 8.3: Typed class constants
    // -------------------------------------------------------------------------

    /** Current package version — embedded in JWT `ghostauth_ver` claim. */
    public const  VERSION = '1.0.0';

    /** Default JWT time-to-live in seconds (1 hour). */
    public const  DEFAULT_JWT_TTL = 3600;

    /** Default OTP length (digits). */
    public const  DEFAULT_OTP_LENGTH = 6;

    /** Default OTP validity window in seconds (5 minutes). */
    public const  DEFAULT_OTP_TTL = 300;

    /** Max failed OTP verification attempts before invalidation. */
    public const  DEFAULT_OTP_MAX_ATTEMPTS = 5;

    /** Default Argon2id memory cost in KiB (64 MiB — OWASP 2023+ recommendation). */
    public const  ARGON2_MEMORY_COST = 65536;

    /** Default Argon2id iteration count. */
    public const  ARGON2_TIME_COST = 4;

    /** Default Argon2id parallelism. */
    public const  ARGON2_THREADS = 2;

    /** JWT claim name used to identify the issuing GhostAuth version. */
    public const  JWT_VERSION_CLAIM = 'ghostauth_ver';

    /**
     * @param string        $appName          Human-readable application name (used in OTP messages).
     * @param string        $jwtSecret        HMAC secret (HS256) or PEM private key (RS256).
     * @param string        $jwtAlgorithm     Signing algorithm: 'HS256' or 'RS256'.
     * @param string        $jwtIssuer        JWT `iss` claim — your application's base URL.
     * @param string        $jwtAudience      JWT `aud` claim — your API identifier.
     * @param int           $jwtTtlSeconds    Token lifetime in seconds.
     * @param string|null   $jwtPublicKey     PEM public key — required for RS256, null for HS256.
     * @param string|null   $pepper           Optional password pepper (from secrets manager).
     * @param string        $otpHmacSecret    HMAC-SHA256 key for OTP storage (≥32 bytes).
     * @param int           $otpLength        Number of digits in generated OTPs.
     * @param int           $otpTtlSeconds    OTP validity window in seconds.
     * @param int           $otpMaxAttempts   Max failed verify attempts before OTP invalidation.
     * @param bool          $autoProvision    Auto-create users on first social/OTP login.
     * @param TokenDriver   $tokenDriver      Token issuance strategy: JWT or Session.
     * @param HashAlgorithm $hashAlgorithm    Password hashing algorithm.
     * @param bool          $mfaEnabled       Whether MFA decorator is active.
     * @param array<string, mixed> $extra     Arbitrary extra settings for custom providers.
     */
    public function __construct(
        public readonly string        $appName,
        public readonly string        $jwtSecret,
        public readonly string        $jwtAlgorithm    = 'HS256',
        public readonly string        $jwtIssuer       = 'https://localhost',
        public readonly string        $jwtAudience     = 'https://localhost',
        public readonly int           $jwtTtlSeconds   = self::DEFAULT_JWT_TTL,
        public readonly ?string       $jwtPublicKey    = null,
        public readonly ?string       $pepper          = null,
        public readonly string        $otpHmacSecret   = '',
        public readonly int           $otpLength       = self::DEFAULT_OTP_LENGTH,
        public readonly int           $otpTtlSeconds   = self::DEFAULT_OTP_TTL,
        public readonly int           $otpMaxAttempts  = self::DEFAULT_OTP_MAX_ATTEMPTS,
        public readonly bool          $autoProvision   = false,
        public readonly TokenDriver   $tokenDriver     = TokenDriver::Jwt,
        public readonly HashAlgorithm $hashAlgorithm   = HashAlgorithm::Argon2id,
        public readonly bool          $mfaEnabled      = false,
        public readonly array         $extra           = [],
    ) {
        $this->validate();
    }

    // -------------------------------------------------------------------------
    // Named constructor — build from a plain array (e.g. from a config file)
    // -------------------------------------------------------------------------

    /**
     * Construct a GhostAuthConfiguration from a plain associative array.
     * Unknown keys are silently ignored; missing required keys throw ConfigurationException.
     *
     * @param  array<string, mixed> $config
     * @return static
     * @throws ConfigurationException
     */
    public static function fromArray(array $config): static
    {
        if (empty($config['app_name'])) {
            throw new ConfigurationException("'app_name' is required in GhostAuth configuration.");
        }
        if (empty($config['jwt_secret'])) {
            throw new ConfigurationException("'jwt_secret' is required in GhostAuth configuration.");
        }
        if (empty($config['otp_hmac_secret'])) {
            throw new ConfigurationException("'otp_hmac_secret' is required (min 32 bytes) in GhostAuth configuration.");
        }

        return new static(
            appName:         (string)  $config['app_name'],
            jwtSecret:       (string)  $config['jwt_secret'],
            jwtAlgorithm:    (string) ($config['jwt_algorithm']   ?? 'HS256'),
            jwtIssuer:       (string) ($config['jwt_issuer']      ?? 'https://localhost'),
            jwtAudience:     (string) ($config['jwt_audience']    ?? 'https://localhost'),
            jwtTtlSeconds:   (int)    ($config['jwt_ttl']         ?? self::DEFAULT_JWT_TTL),
            jwtPublicKey:    isset($config['jwt_public_key']) ? (string) $config['jwt_public_key'] : null,
            pepper:          isset($config['pepper'])         ? (string) $config['pepper']         : null,
            otpHmacSecret:   (string)  $config['otp_hmac_secret'],
            otpLength:       (int)    ($config['otp_length']      ?? self::DEFAULT_OTP_LENGTH),
            otpTtlSeconds:   (int)    ($config['otp_ttl']         ?? self::DEFAULT_OTP_TTL),
            otpMaxAttempts:  (int)    ($config['otp_max_attempts'] ?? self::DEFAULT_OTP_MAX_ATTEMPTS),
            autoProvision:   (bool)   ($config['auto_provision']  ?? false),
            tokenDriver:     TokenDriver::from($config['token_driver'] ?? TokenDriver::Jwt->value),
            hashAlgorithm:   HashAlgorithm::from($config['hash_algorithm'] ?? HashAlgorithm::Argon2id->value),
            mfaEnabled:      (bool)   ($config['mfa_enabled']     ?? false),
            extra:           (array)  ($config['extra']           ?? []),
        );
    }

    // -------------------------------------------------------------------------
    // Validation — called from constructor (readonly class, so post-construct only)
    // -------------------------------------------------------------------------

    /**
     * @throws ConfigurationException
     */
    private function validate(): void
    {
        if ($this->jwtAlgorithm === 'RS256' && $this->jwtPublicKey === null) {
            throw new ConfigurationException(
                'RS256 requires jwtPublicKey to be set for token verification.'
            );
        }

        if (strlen($this->otpHmacSecret) < 32) {
            throw new ConfigurationException(
                'otpHmacSecret must be at least 32 bytes. '
                . 'Generate with: bin2hex(random_bytes(32))'
            );
        }

        if ($this->jwtTtlSeconds < 60) {
            throw new ConfigurationException(
                'jwtTtlSeconds must be at least 60 seconds.'
            );
        }
    }
}
