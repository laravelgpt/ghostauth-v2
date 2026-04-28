<?php

declare(strict_types=1);

namespace GhostAuth\Tokens;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;
use GhostAuth\Contracts\AuthenticatableInterface;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Exceptions\TokenException;
use GhostAuth\GhostAuthConfiguration;
use Psr\SimpleCache\CacheInterface;

/**
 * JwtTokenService
 *
 * Stateless JWT issuance and verification using RS256 (preferred)
 * or HS256 (fallback), backed by the firebase/php-jwt library.
 *
 * Security posture:
 *   - Each token gets a CSPRNG `jti` (JWT ID) for revocation tracking.
 *   - Revocation uses a PSR-16 denylist — the jti is cached for the
 *     token's remaining lifetime. No cache? revoke() is a safe no-op.
 *   - All CSPRNG operations use random_bytes() — never rand()/uniqid().
 *
 * @package GhostAuth\Tokens
 */
final class JwtTokenService implements TokenServiceInterface
{
    private const  DENYLIST_PREFIX = 'ghostauth:jwt:deny:';

    public function __construct(
        private readonly GhostAuthConfiguration $config,
        private readonly ?CacheInterface $denylistCache = null,
    ) {}

    // -------------------------------------------------------------------------
    // TokenServiceInterface
    // -------------------------------------------------------------------------

    /**
     * Issue a signed JWT for the given authenticated user.
     *
     * Standard claims (RFC 7519):
     *   iss, sub, aud, iat, exp, jti
     *
     * GhostAuth extended claims:
     *   email, ghostauth_ver, + user's getJwtClaims()
     *
     * @throws TokenException
     */
    public function issue(AuthenticatableInterface $user, array $extraClaims = []): string
    {
        $now = time();

        // 128 bits of CSPRNG entropy for the JWT ID
        $jti = bin2hex(random_bytes(16));

        $payload = array_merge(
            $user->getJwtClaims(),
            $extraClaims,
            [
                'iss'                                  => $this->config->jwtIssuer,
                'sub'                                  => (string) $user->getAuthIdentifier(),
                'aud'                                  => $this->config->jwtAudience,
                'iat'                                  => $now,
                'exp'                                  => $now + $this->config->jwtTtlSeconds,
                'jti'                                  => $jti,
                GhostAuthConfiguration::JWT_VERSION_CLAIM => GhostAuthConfiguration::VERSION,
            ],
        );

        if ($user->getEmail() !== null) {
            $payload['email'] = $user->getEmail();
        }

        try {
            return JWT::encode(
                payload: $payload,
                key:     $this->config->jwtSecret,
                alg:     $this->config->jwtAlgorithm,
            );
        } catch (\Throwable $e) {
            throw new TokenException('JWT signing failed: ' . $e->getMessage(), previous: $e);
        }
    }

    /**
     * Verify and decode a JWT.
     * Checks: signature, exp, nbf, denylist.
     *
     * @return array<string, mixed>
     * @throws TokenException
     */
    public function verify(string $token): array
    {
        $key = $this->config->jwtAlgorithm === 'RS256'
            ? new Key((string) $this->config->jwtPublicKey, 'RS256')
            : new Key($this->config->jwtSecret, 'HS256');

        try {
            $decoded = JWT::decode($token, $key);
        } catch (ExpiredException $e) {
            throw new TokenException('Token has expired.', 401, $e);
        } catch (BeforeValidException $e) {
            throw new TokenException('Token is not yet valid.', 401, $e);
        } catch (SignatureInvalidException $e) {
            throw new TokenException('Token signature is invalid.', 401, $e);
        } catch (\Throwable $e) {
            throw new TokenException('Token verification failed: ' . $e->getMessage(), 401, $e);
        }

        $payload = (array) $decoded;

        // Check the jti denylist — covers explicit revocations (logout, password change)
        if ($this->denylistCache !== null && isset($payload['jti'])) {
            if ($this->denylistCache->has(self::DENYLIST_PREFIX . $payload['jti'])) {
                throw new TokenException('Token has been revoked.', 401);
            }
        }

        return $payload;
    }

    /**
     * Revoke a token by adding its jti to the denylist cache.
     * TTL is set to the token's remaining lifetime — auto-cleans itself.
     */
    public function revoke(string $token): bool
    {
        if ($this->denylistCache === null) {
            return false;
        }

        try {
            // Decode without full validation — we need jti even for near-expired tokens
            $parts   = explode('.', $token);
            $payload = json_decode(
                base64_decode(strtr($parts[1] ?? '', '-_', '+/')),
                associative: true,
            );
        } catch (\Throwable) {
            return false;
        }

        if (! is_array($payload) || ! isset($payload['jti'], $payload['exp'])) {
            return false;
        }

        $ttl = max(1, (int) $payload['exp'] - time());

        return $this->denylistCache->set(
            self::DENYLIST_PREFIX . $payload['jti'],
            true,
            $ttl,
        );
    }
}
