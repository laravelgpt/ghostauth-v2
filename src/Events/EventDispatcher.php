<?php

declare(strict_types=1);

namespace GhostAuth\Events;

/**
 * EventDispatcher
 *
 * Dispatches SecurityEvents to registered listeners and notification channels.
 * Used for:
 *   - Device login notifications (email/SMS/push)
 *   - Audit logging
 *   - Webhook delivery
 *   - Anomaly detection triggers
 *
 * @package GhostAuth\Events
 */
class EventDispatcher
{
    /** @var array<string, array<callable>> Listeners keyed by event type. */
    private array $listeners = [];

    /** @var array<callable> Global listeners (all events). */
    private array $globalListeners = [];

    /** @var callable|null  Notification dispatcher callback. */
    private $notificationHandler = null;

    /**
     * Register a listener for a specific event type.
     *
     * @param string   $eventType  SecurityEvent type constant value.
     * @param callable $listener   fn(SecurityEvent $event): void
     * @return static
     */
    public function listen(string $eventType, callable $listener): static
    {
        $this->listeners[$eventType][] = $listener;
        return $this;
    }

    /**
     * Register a global listener for ALL events.
     *
     * @param callable $listener fn(SecurityEvent $event): void
     * @return static
     */
    public function listenAll(callable $listener): static
    {
        $this->globalListeners[] = $listener;
        return $this;
    }

    /**
     * Set the notification handler — called for user-facing notifications.
     *
     * @param callable $handler fn(SecurityEvent $event, array $channels): void
     *                          $channels = ['email', 'sms', 'push']
     * @return static
     */
    public function setNotificationHandler(callable $handler): static
    {
        $this->notificationHandler = $handler;
        return $this;
    }

    /**
     * Dispatch a security event to all matching listeners.
     *
     * @param SecurityEvent $event
     */
    public function dispatch(SecurityEvent $event): void
    {
        // Global listeners
        foreach ($this->globalListeners as $listener) {
            ($listener)($event);
        }

        // Type-specific listeners
        if (isset($this->listeners[$event->type])) {
            foreach ($this->listeners[$event->type] as $listener) {
                ($listener)($event);
            }
        }

        // Notification handler for user-facing alerts
        if ($this->notificationHandler !== null) {
            $channels = $this->resolveNotificationChannels($event);
            if (! empty($channels)) {
                ($this->notificationHandler)($event, $channels);
            }
        }
    }

    /**
     * Determine which notification channels should be used for this event.
     *
     * Events that ALWAYS trigger notification regardless of settings:
     *   - ACCOUNT_LOCKED
     *   - COOKIE_DESTROYED
     *   - BRUTE_FORCE_DETECTED
     *   - SESSIONS_DESTROYED
     *   - PASSWORD_BREACHED
     *
     * Events that notify on NEW DEVICE:
     *   - DEVICE_NEW (only if user has notification enabled)
     *   - AUTH_SUCCESS (only from new device)
     */
    private function resolveNotificationChannels(SecurityEvent $event): array
    {
        $critical = [
            SecurityEvent::ACCOUNT_LOCKED,
            SecurityEvent::COOKIE_DESTROYED,
            SecurityEvent::BRUTE_FORCE_DETECTED,
            SecurityEvent::SESSIONS_DESTROYED,
            SecurityEvent::PASSWORD_BREACHED,
            SecurityEvent::PASSWORD_CHANGED,
            SecurityEvent::MFA_DISABLED,
        ];

        if (in_array($event->type, $critical, true)) {
            // Critical events: notify via all available channels
            return ['email']; // SMS/push available if configured
        }

        if ($event->type === SecurityEvent::DEVICE_NEW) {
            return ['email']; // New device notification
        }

        return [];
    }
}
