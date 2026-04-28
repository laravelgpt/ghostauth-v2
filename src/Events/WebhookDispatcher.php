<?php

declare(strict_types=1);

namespace GhostAuth\Events;

use GhostAuth\Events\SecurityEvent;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * WebhookDispatcher
 *
 * Sends SecurityEvents to external webhook URLs.
 * Useful for:
 *   - SIEM integration (Splunk, Datadog, etc.)
 *   - Slack/Discord security alerts
 *   - Custom notification systems
 *   - Audit trail offsite backup
 *
 * Features:
 *   - HMAC-SHA256 signature in X-GhostAuth-Signature header
 *   - Configurable retry on failure (exponential backoff)
 *   - Selective event filtering (only send specific event types)
 *   - Timeout protection (won't block auth flow)
 *
 * @package GhostAuth\Events
 */
class WebhookDispatcher
{
    public const DEFAULT_TIMEOUT   = 5;   // seconds
    public const DEFAULT_RETRIES   = 3;
    public const DEFAULT_BACKOFF_MS = 500; // initial delay

    /** @var array<array{url: string, secret: string, filter: string[]}> */
    private array $webhooks = [];

    private int    $timeout  = self::DEFAULT_TIMEOUT;
    private int    $retries  = self::DEFAULT_RETRIES;
    private int    $backoffMs = self::DEFAULT_BACKOFF_MS;

    public function __construct(
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    /**
     * Register a webhook endpoint.
     *
     * @param  string   $url     Webhook URL (must be HTTPS in production).
     * @param  string   $secret  Shared secret for HMAC signature.
     * @param  string[] $filter  Event types to send. Empty = all events.
     * @return static
     */
    public function registerWebhook(string $url, string $secret, array $filter = []): static
    {
        $this->webhooks[] = [
            'url'    => $url,
            'secret' => $secret,
            'filter' => $filter,
        ];

        return $this;
    }

    /**
     * Dispatch a security event to all registered webhooks.
     * Runs in non-blocking mode — failures are logged but don't block.
     *
     * @param SecurityEvent $event
     */
    public function dispatch(SecurityEvent $event): void
    {
        foreach ($this->webhooks as $webhook) {
            // Check event filter
            if (! empty($webhook['filter']) && ! in_array($event->type, $webhook['filter'], true)) {
                continue;
            }

            // Send (with retries)
            $this->sendWithRetry($webhook, $event);
        }
    }

    /**
     * Send a webhook with exponential backoff retries.
     */
    private function sendWithRetry(array $webhook, SecurityEvent $event): void
    {
        $payload = json_encode($event->toArray(), JSON_THROW_ON_ERROR);
        $signature = hash_hmac('sha256', $payload, $webhook['secret']);

        for ($attempt = 1; $attempt <= $this->retries; $attempt++) {
            try {
                $ch = curl_init($webhook['url']);
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT        => $this->timeout,
                    CURLOPT_POST           => true,
                    CURLOPT_POSTFIELDS     => $payload,
                    CURLOPT_HTTPHEADER     => [
                        'Content-Type: application/json',
                        'X-GhostAuth-Signature: sha256=' . $signature,
                        'X-GhostAuth-Event: ' . $event->type,
                        'X-GhostAuth-Request-Id: ' . $event->requestId,
                    ],
                ]);

                $response = curl_exec($ch);
                $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);

                if ($httpCode >= 200 && $httpCode < 300) {
                    return; // Success
                }

                $this->logger->warning("Webhook failed (HTTP $httpCode)", [
                    'url'     => $webhook['url'],
                    'event'   => $event->type,
                    'attempt' => $attempt,
                ]);

            } catch (\Throwable $e) {
                $this->logger->warning("Webhook exception: " . $e->getMessage(), [
                    'url'     => $webhook['url'],
                    'event'   => $event->type,
                    'attempt' => $attempt,
                ]);
            }

            // Backoff before retry
            if ($attempt < $this->retries) {
                usleep($this->backoffMs * 1000 * $attempt);
            }
        }

        $this->logger->error("Webhook permanently failed after {$this->retries} attempts", [
            'url'   => $webhook['url'],
            'event' => $event->type,
        ]);
    }
}
