<?php

declare(strict_types=1);

namespace GhostAuth\Mfa;

use GhostAuth\Contracts\MfaHandlerInterface;
use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Contracts\UserRepositoryInterface;
use GhostAuth\DTO\AuthResult;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * WebAuthnMfaHandler (v2)
 *
 * Passkey/WebAuthn MFA handler. Supports:
 *   - Registration of new passkeys
 *   - Authentication via existing passkeys
 *   - Multiple passkeys per user
 *
 * @package GhostAuth\Mfa
 */
final class WebAuthnMfaHandler implements MfaHandlerInterface
{
    public const BRIDGE_PREFIX = 'ghostauth:mfa:webauthn:';
    public const BRIDGE_TTL    = 300;

    public function __construct(
        private readonly CacheInterface        $cache,
        private readonly TokenServiceInterface $tokenService,
        private readonly UserRepositoryInterface $userRepo,
        private readonly string                $rpId,
        private readonly string                $rpName,
        private readonly string                $origin,
        private $getCredential,  // fn(string $credId): ?array{user_id: mixed, public_key: string, alg: int, counter: int}
        private $saveCredential, // fn(mixed $userId, string $credId, string $pem, int $alg, int $counter): void
        private readonly LoggerInterface       $logger          = new NullLogger(),
    ) {}

    // -------------------------------------------------------------------------
    // MfaHandlerInterface — used for the verification step after passkey auth
    // -------------------------------------------------------------------------

    /**
     * Complete passkey authentication by verifying the assertion.
     *
     * @param  string               $mfaToken    Bridge token from challenge creation.
     * @param  array<string, mixed> $credentials WebAuthn assertion data from browser.
     * @return AuthResult
     */
    public function handle(string $mfaToken, array $credentials): AuthResult
    {
        $context = $this->cache->get(self::BRIDGE_PREFIX . $mfaToken);

        if (! is_array($context)) {
            return AuthResult::failed('WEBAUTHN_TOKEN_EXPIRED', 'Passkey session expired.');
        }

        $rawChallenge = $context['raw_challenge'];
        $credentialId = $context['credential_id'] ?? null;

        // If no credential_id was pre-selected (resident credential flow),
        // the browser sends it in the response
        $credId = $credentialId
            ?? ($credentials['credential_id'] ?? null);

        if ($credId === null) {
            return AuthResult::failed('WEBAUTHN_NO_CREDENTIAL', 'No credential provided.');
        }

        $stored = ($this->getCredential)($credId);

        if ($stored === null) {
            return AuthResult::failed('WEBAUTHN_CREDENTIAL_NOT_FOUND', 'Credential not registered.');
        }

        try {
            $result = WebAuthnAuthenticator::verifyAuthentication(
                clientDataJson:    $credentials['client_data'] ?? [],
                authenticatorData: $credentials['authenticator_data'] ?? [],
                signature:         $credentials['signature'] ?? '',
                rawChallenge:      $rawChallenge,
                publicKeyPem:      $stored['public_key'],
                alg:               $stored['alg'],
                origin:            $this->origin,
                rpId:              $this->rpId,
            );

            // Update counter (prevent cloned authenticator replay)
            if ($result['counter'] > $stored['counter']) {
                ($this->saveCredential)(
                    $stored['user_id'],
                    $credId,
                    $stored['public_key'],
                    $stored['alg'],
                    $result['counter'],
                );
            }

        } catch (\RuntimeException $e) {
            $this->logger->warning('WebAuthnMfaHandler: assertion failed', [
                'error' => $e->getMessage(),
            ]);

            return AuthResult::failed('WEBAUTHN_VERIFICATION_FAILED', $e->getMessage());
        }

        // Consume bridge token
        $this->cache->delete(self::BRIDGE_PREFIX . $mfaToken);

        $user = $this->userRepo->findById($stored['user_id']);

        if ($user === null) {
            return AuthResult::failed('USER_NOT_FOUND', 'User not found.');
        }

        $token = $this->tokenService->issue($user, ['mfa_verified' => 'webauthn']);

        $this->logger->info('WebAuthnMfaHandler: passkey auth successful', [
            'user_id' => $stored['user_id'],
        ]);

        return AuthResult::authenticated($user, $token, ['mfa_method' => 'webauthn']);
    }

    // -------------------------------------------------------------------------
    // WebAuthn-specific: Registration (credential creation)
    // -------------------------------------------------------------------------

    /**
     * Generate a registration challenge. Call this BEFORE the browser calls
     * navigator.credentials.create().
     *
     * @param  mixed  $userId
     * @param  string $username
     * @param  string $displayName
     * @return array  Challenge data to send to the browser (JSON).
     */
    public function createRegistrationChallenge(mixed $userId, string $username, string $displayName): array
    {
        $challenge = WebAuthnAuthenticator::createRegistrationChallenge(
            $userId, $username, $displayName, $this->rpId, $this->rpName,
        );

        // Store raw challenge for later verification
        $this->cache->set(
            self::BRIDGE_PREFIX . 'reg:' . $challenge['challenge'],
            $challenge['raw_challenge'],
            WebAuthnAuthenticator::CHALLENGE_TTL,
        );

        // Remove raw_challenge from the response (don't send to browser)
        unset($challenge['raw_challenge']);

        return $challenge;
    }

    /**
     * Verify and store a new passkey credential.
     * Call this AFTER the browser calls navigator.credentials.create() and
     * sends back the AttestationObject + clientDataJSON.
     *
     * @param  mixed                $userId
     * @param  string               $challengeId  The challenge ID from createRegistrationChallenge().
     * @param  array<string, mixed> $clientDataJson   Decoded clientDataJSON.
     * @param  array<string, mixed> $attestationObj   Decoded AttestationObject.
     * @return array{credential_id: string, success: bool, error: string|null}
     */
    public function completeRegistration(
        mixed $userId,
        string $challengeId,
        array $clientDataJson,
        array $attestationObj,
    ): array {
        $rawChallenge = $this->cache->get(self::BRIDGE_PREFIX . 'reg:' . $challengeId);

        if (! is_string($rawChallenge)) {
            return ['credential_id' => '', 'success' => false, 'error' => 'Registration challenge expired.'];
        }

        try {
            $cred = WebAuthnAuthenticator::verifyRegistration(
                $clientDataJson,
                $attestationObj,
                $rawChallenge,
                $this->origin,
                $this->rpId,
            );
        } catch (\RuntimeException $e) {
            return ['credential_id' => '', 'success' => false, 'error' => $e->getMessage()];
        }

        // Store credential
        ($this->saveCredential)(
            $userId,
            $cred['credential_id'],
            $cred['public_key'],
            $cred['alg'],
            $cred['counter'],
        );

        // Clean up challenge
        $this->cache->delete(self::BRIDGE_PREFIX . 'reg:' . $challengeId);

        $this->logger->info('WebAuthnMfaHandler: passkey registered', [
            'user_id'       => $userId,
            'credential_id' => $cred['credential_id'],
        ]);

        return ['credential_id' => $cred['credential_id'], 'success' => true, 'error' => null];
    }

    // -------------------------------------------------------------------------
    // WebAuthn-specific: Authentication challenge
    // -------------------------------------------------------------------------

    /**
     * Generate an authentication challenge. Call BEFORE navigator.credentials.get().
     *
     * @param  string|null $allowedCredentialId  Optional: limit to a specific credential.
     * @param  array<string> $allowedCredentialIds  Optional: list of allowed credential IDs.
     * @return array{challenge: string, rp_id: string, timeout: int, allow_credentials: array, token: string}
     */
    public function createAuthenticationChallenge(
        ?string $allowedCredentialId = null,
        array $allowedCredentialIds = [],
    ): array {
        $challenge = WebAuthnAuthenticator::createAuthenticationChallenge($this->rpId);

        // Store context for verification
        $context = [
            'raw_challenge'   => $challenge['raw_challenge'],
            'credential_id'   => $allowedCredentialId,
        ];

        $token = bin2hex(random_bytes(32));

        $this->cache->set(self::BRIDGE_PREFIX . $token, $context, self::BRIDGE_TTL);

        $allowCredentials = [];

        if ($allowedCredentialId !== null) {
            $allowCredentials[] = [
                'type' => 'public-key',
                'id'   => $allowedCredentialId,
            ];
        }

        foreach ($allowedCredentialIds as $id) {
            $allowCredentials[] = [
                'type' => 'public-key',
                'id'   => $id,
            ];
        }

        // Remove raw_challenge from response
        unset($challenge['raw_challenge']);

        return [
            'challenge'        => $challenge['challenge'],
            'rp_id'            => $challenge['rp_id'],
            'timeout'          => $challenge['timeout'],
            'allow_credentials' => $allowCredentials,
            'token'            => $token,
        ];
    }

    // -------------------------------------------------------------------------
    // Enroll is not used for WebAuthn — use createRegistrationChallenge instead
    // -------------------------------------------------------------------------

    public function enroll(mixed $userId, string $email, string $issuer): array
    {
        // WebAuthn doesn't use a shared secret — credentials are generated by the device.
        // This method is provided for interface compliance but delegates to registration.
        return $this->createRegistrationChallenge($userId, $email, $issuer);
    }

    public function isAvailable(): bool
    {
        return function_exists('openssl_verify');
    }
}
