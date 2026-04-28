<?php

declare(strict_types=1);

namespace GhostAuth\Providers;

use GhostAuth\Contracts\AuthenticationStrategy;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Contracts\UserRepositoryInterface;
use GhostAuth\DTO\AuthResult;
use GhostAuth\Exceptions\GhostAuthException;
use GhostAuth\Security\MagicLink;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * MagicLinkProvider
 *
 * Passwordless authentication via magic links sent to email.
 *
 * Flow:
 *   Phase 1 (send): credentials = ['email' => '...'] → generate link, return pending
 *   Phase 2 (verify): credentials = ['email' => '...', 'token' => '...'] → authenticate
 *
 * @package GhostAuth\Providers
 */
final class MagicLinkProvider implements AuthenticationStrategy
{
    public const MAGIC_TTL = 900; // 15 minutes

    public function __construct(
        private readonly MagicLink              $magicLink,
        private readonly UserRepositoryInterface $userRepo,
        private readonly TokenServiceInterface   $tokenService,
        private $sendLink,  // fn(string $email, string $url): void
        private readonly string                  $baseUrl,   // e.g. 'https://myapp.com/auth/magic/verify'
        private readonly bool                    $enabled    = true,
        private readonly bool                    $bindIp     = true,
        private readonly LoggerInterface         $logger     = new NullLogger(),
    ) {}

    public function authenticate(array $credentials): AuthResult
    {
        $this->guardEnabled();

        // Phase 2: verify token
        if (! empty($credentials['token'])) {
            return $this->verify(
                (string) $credentials['email'],
                (string) $credentials['token'],
                $credentials['ip'] ?? null,
            );
        }

        // Phase 1: send magic link
        return $this->send((string) $credentials['email']);
    }

    public function name(): string
    {
        return 'magic_link';
    }

    public function isAvailable(): bool
    {
        return $this->enabled;
    }

    // =========================================================================
    // Phase 1: Send magic link
    // =========================================================================

    private function send(string $email): AuthResult
    {
        $email = strtolower(trim($email));
        $user  = $this->userRepo->findByEmail($email);

        if ($user === null) {
            // Don't reveal whether email exists (same error as wrong password)
            return AuthResult::failed(
                'MAGIC_LINK_SENT',
                'If an account with that email exists, you will receive a login link.',
            );
        }

        $token = $this->magicLink->generateToken(
            $email,
            $user->getAuthIdentifier(),
            $_SERVER['REMOTE_ADDR'] ?? '',
        );

        $url = $this->magicLink->generateUrl($token, $this->baseUrl);

        // Send the magic link email
        ($this->sendLink)($email, $url);

        $this->logger->info('MagicLinkProvider: magic link sent', [
            'email' => $email,
        ]);

        return AuthResult::pendingOtp([
            'channel'    => 'email',
            'expires_in' => self::MAGIC_TTL,
            'message'    => 'A login link has been sent to your email address.',
        ]);
    }

    // =========================================================================
    // Phase 2: Verify magic link token
    // =========================================================================

    private function verify(string $email, string $token, ?string $currentIp): AuthResult
    {
        $email = strtolower(trim($email));

        $result = $this->magicLink->verify($token, $this->bindIp ? $currentIp : null);

        if (! $result['success']) {
            return AuthResult::failed(
                'MAGIC_LINK_INVALID',
                $result['error'] ?? 'Invalid or expired magic link.',
            );
        }

        // Find the user
        $user = $this->userRepo->findById($result['user_id']);

        if ($user === null) {
            return AuthResult::failed('USER_NOT_FOUND', 'User account not found.');
        }

        // Issue token
        $jwt = $this->tokenService->issue($user, ['auth_method' => 'magic_link']);

        $this->logger->info('MagicLinkProvider: magic link authentication successful', [
            'user_id' => $user->getAuthIdentifier(),
        ]);

        return AuthResult::authenticated($user, $jwt, ['auth_method' => 'magic_link']);
    }

    private function guardEnabled(): void
    {
        if (! $this->enabled) {
            throw new GhostAuthException('MagicLinkProvider is disabled.');
        }
    }
}
