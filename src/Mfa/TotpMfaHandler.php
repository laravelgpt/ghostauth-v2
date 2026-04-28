<?php

declare(strict_types=1);

namespace GhostAuth\Mfa;

use GhostAuth\Contracts\MfaHandlerInterface;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Contracts\UserRepositoryInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Exceptions\GhostAuthException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * TotpMfaHandler (v2)
 *
 * TOTP MFA handler — verifies TOTP/backup codes, issues final session token.
 * Bridges the gap between primary auth (pendingMfa) and full authentication.
 *
 * @package GhostAuth\Mfa
 */
final class TotpMfaHandler implements MfaHandlerInterface
{
    public const BRIDGE_PREFIX = 'ghostauth:mfa:bridge:';
    public const BRIDGE_TTL    = 300;

    public function __construct(
        private readonly CacheInterface        $cache,
        private readonly TokenServiceInterface $tokenService,
        private readonly UserRepositoryInterface $userRepo,
        private $getSecret,       // fn(mixed $userId): ?string
        private $saveSecret,      // fn(mixed $userId, string $secret): void
        private $getBackupCodes,  // fn(mixed $userId): array
        private $saveBackupCodes, // fn(mixed $userId, array $hashes): void
        private readonly string                $appName          = 'GhostAuth',
        private readonly int                   $totpDigits       = TotpAuthenticator::DEFAULT_DIGITS,
        private readonly int                   $totpPeriod       = TotpAuthenticator::DEFAULT_PERIOD,
        private readonly int                   $totpLeeway       = 1,
        private readonly LoggerInterface       $logger           = new NullLogger(),
    ) {}

    public function handle(string $mfaToken, array $credentials): AuthResult
    {
        $userId = $this->cache->get(self::BRIDGE_PREFIX . $mfaToken);

        if ($userId === null) {
            return AuthResult::failed('MFA_TOKEN_EXPIRED', 'MFA session expired. Please log in again.');
        }

        // Try TOTP
        if (! empty($credentials['totp_code'])) {
            $secret = ($this->getSecret)($userId);

            if ($secret === null) {
                return AuthResult::failed('MFA_NOT_CONFIGURED', 'MFA not configured for this account.');
            }

            if (! TotpAuthenticator::verify(
                $secret, (string) $credentials['totp_code'],
                $this->totpDigits, $this->totpPeriod, $this->totpLeeway,
            )) {
                return AuthResult::failed('MFA_CODE_INVALID', 'Invalid authenticator code.');
            }
        }
        // Try backup code
        elseif (! empty($credentials['backup_code'])) {
            if (! $this->consumeBackupCode($userId, (string) $credentials['backup_code'])) {
                return AuthResult::failed('BACKUP_CODE_INVALID', 'Invalid or already-used backup code.');
            }
        } else {
            return AuthResult::failed('MFA_MISSING_CREDENTIALS', 'No MFA credentials provided.');
        }

        // Consume bridge token
        $this->cache->delete(self::BRIDGE_PREFIX . $mfaToken);

        // Get user and issue final token
        $user = $this->userRepo->findById($userId);

        if ($user === null) {
            return AuthResult::failed('USER_NOT_FOUND', 'User not found.');
        }

        $token = $this->tokenService->issue($user, ['mfa_verified' => 'totp']);

        $this->logger->info('TotpMfaHandler: MFA verified', ['user_id' => $userId]);

        return AuthResult::authenticated($user, $token, ['mfa_method' => 'totp']);
    }

    public function enroll(mixed $userId, string $email, string $issuer): array
    {
        $secret      = TotpAuthenticator::generateSecret();
        $backupCodes = TotpAuthenticator::generateBackupCodes();
        $hashedCodes = TotpAuthenticator::hashBackupCodes($backupCodes);

        ($this->saveSecret)($userId, $secret);
        ($this->saveBackupCodes)($userId, $hashedCodes);

        return [
            'secret'           => $secret,
            'backup_codes'     => $backupCodes,
            'provisioning_uri' => TotpAuthenticator::provisioningUri($secret, $email, $issuer),
        ];
    }

    public function isAvailable(): bool
    {
        return true;
    }

    private function consumeBackupCode(mixed $userId, string $code): bool
    {
        $hashedCodes = ($this->getBackupCodes)($userId);

        if (empty($hashedCodes)) {
            return false;
        }

        if (TotpAuthenticator::verifyBackupCode($code, $hashedCodes) === null) {
            return false;
        }

        // Remove the matched hash
        $remaining = array_filter($hashedCodes, fn($h) => ! password_verify($code, $h));
        ($this->saveBackupCodes)($userId, $remaining);

        return true;
    }
}
