<?php

declare(strict_types=1);

namespace GhostAuth\Middleware;

use GhostAuth\Contracts\TokenServiceInterface;
use GhostAuth\Exceptions\SessionException;
use GhostAuth\Exceptions\TokenException;
use GhostAuth\GhostAuthConfiguration;
use GhostAuth\Security\DeviceFingerprint;
use GhostAuth\Security\SessionGuard;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * GhostAuthMiddleware — "The Ghost"
 *
 * A PSR-15 middleware that intercepts every HTTP request and validates
 * authentication via TWO modes:
 *
 *   Mode 1: Bearer JWT (Authorization: Bearer <token>)
 *     - Direct token verification via TokenServiceInterface
 *     - Stateless — no server-side state required
 *
 *   Mode 2: Encrypted Session Cookie (ghostauth_session)
 *     - AES-256-CTR encrypted + HMAC-SHA256 signed cookie
 *     - Device fingerprint validation (IP + UA binding)
 *     - IP change cookie destroyer — destroys ALL sessions on mismatch
 *     - Session rotation on successful validation
 *
 * On success:
 *   Decoded claims attached as `ghostauth.claims` attribute.
 *   Raw token or cookie value as `ghostauth.token` / `ghostauth.cookie`.
 *   Auth mode as `ghostauth.auth_mode` ('bearer' | 'cookie').
 *
 * On failure:
 *   401 JSON response — next handler never called.
 *
 * @package GhostAuth\Middleware
 */
final class GhostAuthMiddleware implements MiddlewareInterface
{
    public const  CLAIMS_ATTRIBUTE = 'ghostauth.claims';
    public const  TOKEN_ATTRIBUTE  = 'ghostauth.token';
    public const  COOKIE_ATTRIBUTE = 'ghostauth.cookie';
    public const  MODE_ATTRIBUTE   = 'ghostauth.auth_mode';
    public const  AUTH_HEADER      = 'Authorization';
    public const  BEARER_PREFIX    = 'Bearer ';

    public function __construct(
        private readonly TokenServiceInterface    $tokenService,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly SessionGuard             $sessionGuard,
        private readonly GhostAuthConfiguration   $config,
        private readonly array                    $excludedPaths = [],
        private readonly bool                     $strict        = true,
        private readonly LoggerInterface          $logger        = new NullLogger(),
    ) {}

    /**
     * Intercept, validate, and optionally forward the request.
     *
     * Priority: Bearer token > Session cookie > Anonymous (if non-strict) > 401
     */
    public function process(
        ServerRequestInterface  $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $path = $request->getUri()->getPath();

        if ($this->isExcluded($path)) {
            return $handler->handle($request);
        }

        // ── Mode 1: Bearer JWT ──────────────────────────────────────────────
        $bearer = $this->extractBearer($request);

        if ($bearer !== null) {
            return $this->handleBearer($request, $handler, $bearer);
        }

        // ── Mode 2: Encrypted session cookie ────────────────────────────────
        $cookieValue = $this->extractCookie($request);

        if ($cookieValue !== null) {
            return $this->handleCookie($request, $handler, $cookieValue);
        }

        // ── No credentials ──────────────────────────────────────────────────
        if (! $this->strict) {
            return $handler->handle(
                $request->withAttribute(self::CLAIMS_ATTRIBUTE, null)
                         ->withAttribute(self::MODE_ATTRIBUTE, 'anonymous')
            );
        }

        return $this->unauthorizedResponse('Missing authentication credentials.');
    }

    // =========================================================================
    // Mode 1: Bearer JWT handler
    // =========================================================================

    private function handleBearer(
        ServerRequestInterface  $request,
        RequestHandlerInterface $handler,
        string                  $token,
    ): ResponseInterface {
        try {
            $claims = $this->tokenService->verify($token);
        } catch (TokenException $e) {
            $this->logger->warning('GhostAuthMiddleware: Bearer token invalid', [
                'path'  => $request->getUri()->getPath(),
                'error' => $e->getMessage(),
            ]);

            return $this->unauthorizedResponse($e->getMessage());
        }

        $this->logger->debug('GhostAuthMiddleware: Bearer token verified', [
            'sub'  => $claims['sub'] ?? null,
            'path' => $request->getUri()->getPath(),
        ]);

        return $handler->handle(
            $request
                ->withAttribute(self::CLAIMS_ATTRIBUTE, $claims)
                ->withAttribute(self::TOKEN_ATTRIBUTE, $token)
                ->withAttribute(self::MODE_ATTRIBUTE, 'bearer')
        );
    }

    // =========================================================================
    // Mode 2: Encrypted session cookie handler
    // =========================================================================

    private function handleCookie(
        ServerRequestInterface  $request,
        RequestHandlerInterface $handler,
        string                  $cookieValue,
    ): ResponseInterface {
        // Build current device fingerprint from request
        $fingerprint = DeviceFingerprint::fromRequest(
            $request->getServerParams(),
            $this->config->extra['fingerprint_salt'] ?? '',
        );

        try {
            $session = $this->sessionGuard->readSession($cookieValue, $fingerprint);
        } catch (SessionException $e) {
            $this->logger->warning('GhostAuthMiddleware: session cookie invalid', [
                'path'  => $request->getUri()->getPath(),
                'error' => $e->getMessage(),
            ]);

            return $this->unauthorizedResponse($e->getMessage());
        }

        $claims = $session['claims'] ?? [];

        $this->logger->debug('GhostAuthMiddleware: session cookie verified + fingerprint matched', [
            'sub'     => $claims['sub'] ?? null,
            'user_id' => $session['user_id'] ?? null,
            'path'    => $request->getUri()->getPath(),
        ]);

        // Rotate session on every successful read (prevents fixation)
        $newCookie = $this->sessionGuard->rotateSession(
            $session['token'],
            $fingerprint,
            $session['user_id'],
        );

        // Build authenticated request
        $authRequest = $request
            ->withAttribute(self::CLAIMS_ATTRIBUTE, $claims)
            ->withAttribute(self::TOKEN_ATTRIBUTE, $session['token'])
            ->withAttribute(self::COOKIE_ATTRIBUTE, $newCookie)
            ->withAttribute(self::MODE_ATTRIBUTE, 'cookie');

        $response = $handler->handle($authRequest);

        // Attach the rotated cookie to the response
        $response = $response->withHeader('Set-Cookie', $this->buildSetCookieHeader($newCookie));

        return $response;
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    private function extractBearer(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine(self::AUTH_HEADER);

        if ($header === '' || ! str_starts_with($header, self::BEARER_PREFIX)) {
            return null;
        }

        $token = substr($header, strlen(self::BEARER_PREFIX));

        return $token !== '' ? $token : null;
    }

    private function extractCookie(ServerRequestInterface $request): ?string
    {
        $cookies = $request->getCookieParams();
        $cookie  = $cookies[SessionGuard::COOKIE_NAME] ?? null;

        return is_string($cookie) && $cookie !== '' ? $cookie : null;
    }

    private function isExcluded(string $path): bool
    {
        foreach ($this->excludedPaths as $excluded) {
            if ($path === $excluded || str_starts_with($path, rtrim($excluded, '/') . '/')) {
                return true;
            }
        }

        return false;
    }

    private function unauthorizedResponse(string $message): ResponseInterface
    {
        $body = json_encode(
            [
                'error'         => 'UNAUTHORIZED',
                'message'       => $message,
                'ghostauth_ver' => GhostAuthConfiguration::VERSION,
            ],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE,
        );

        $response = $this->responseFactory
            ->createResponse(401)
            ->withHeader('Content-Type', 'application/json; charset=utf-8')
            ->withHeader('WWW-Authenticate', 'Bearer realm="GhostAuth"');

        $response->getBody()->write($body);

        return $response;
    }

    private function buildSetCookieHeader(string $cookieValue): string
    {
        $parts = [
            SessionGuard::COOKIE_NAME . '=' . $cookieValue,
            'Path=' . SessionGuard::COOKIE_PATH,
            'HttpOnly',
            'Secure',
            'SameSite=' . SessionGuard::COOKIE_SAME_SITE,
            'Max-Age=' . SessionGuard::COOKIE_LIFETIME,
        ];

        if (SessionGuard::COOKIE_DOMAIN !== '') {
            $parts[] = 'Domain=' . SessionGuard::COOKIE_DOMAIN;
        }

        return implode('; ', $parts);
    }
}
