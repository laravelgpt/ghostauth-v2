<?php

declare(strict_types=1);

namespace GhostAuth\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * AnomalyDetector
 *
 * Detects unusual login patterns that may indicate account compromise.
 *
 * Detection heuristics:
 *   1. Impossible travel — login from two countries within < N hours
 *   2. Unusual hour — login outside user's typical login hours
 *   3. New country — first login from a country never seen before
 *   4. Velocity — more than N successful logins in 1 hour
 *   5. Rapid geographic jumps — login from 3+ countries in 24 hours
 *
 * @package GhostAuth\Security
 */
class AnomalyDetector
{
    public const HISTORY_KEY = 'ghostauth:login_history:';
    public const HISTORY_TTL = 2_592_000; // 30 days

    public function __construct(
        private readonly CacheInterface $cache,
        private $geoLookup,               // fn(string $ip): array{country: string, city: string}
        private readonly int              $impossibleTravelHours = 2,
        private readonly int              $maxLoginsPerHour = 5,
        private readonly array            $normalHours = [6, 23],
    ) {}

    /**
     * Record a successful login for anomaly tracking.
     */
    public function recordLogin(mixed $userId, string $ip, int $hour): ?string
    {
        $geo = ($this->geoLookup)($ip);
        $country = isset($geo['country']) ? $geo['country'] : '??';

        $history = $this->getHistory($userId);
        $history[] = [
            'ip'      => $ip,
            'country' => $country,
            'city'    => isset($geo['city']) ? $geo['city'] : '',
            'hour'    => $hour,
            'time'    => time(),
        ];

        if (count($history) > 100) {
            $history = array_slice($history, -100);
        }

        $key = self::HISTORY_KEY . (string) $userId;
        $this->cache->set($key, $history, self::HISTORY_TTL);

        return $country;
    }

    /**
     * Analyze a login for anomalies.
     *
     * @return array{anomalies: array<string, array{severity: string, message: string}>, risk_score: int}
     */
    public function analyze(mixed $userId, string $ip, int $hour): array
    {
        $history   = $this->getHistory($userId);
        $geo       = ($this->geoLookup)($ip);
        $anomalies = [];

        if (empty($history)) {
            return ['anomalies' => [], 'risk_score' => 0];
        }

        // ── 1. Impossible travel ──────────────────────────────────────────
        $lastLogin = end($history);
        if (is_array($lastLogin) && isset($lastLogin['country'], $lastLogin['time'])) {
            $hoursSince = (time() - $lastLogin['time']) / 3600;
            $lastCountry = $lastLogin['country'];
            $currentCountry = isset($geo['country']) ? $geo['country'] : '';

            if ($hoursSince < $this->impossibleTravelHours
                && $lastCountry !== '??'
                && $currentCountry !== ''
                && $currentCountry !== '??'
                && $lastCountry !== $currentCountry
            ) {
                $anomalies['impossible_travel'] = [
                    'severity' => 'critical',
                    'message'  => sprintf(
                        'Login from %s just %.1f hours after login from %s.',
                        $currentCountry,
                        $hoursSince,
                        $lastCountry
                    ),
                ];
            }
        }

        // ── 2. Unusual hour ───────────────────────────────────────────────
        if ($hour < $this->normalHours[0] || $hour > $this->normalHours[1]) {
            $anomalies['unusual_hour'] = [
                'severity' => 'warning',
                'message'  => "Login at hour $hour is outside normal hours ({$this->normalHours[0]}:00–{$this->normalHours[1]}:00).",
            ];
        }

        // ── 3. New country ────────────────────────────────────────────────
        $knownCountries = [];
        foreach ($history as $entry) {
            if (isset($entry['country']) && $entry['country'] !== '??') {
                $knownCountries[] = $entry['country'];
            }
        }
        $knownCountries = array_unique($knownCountries);
        $currentCountry = isset($geo['country']) ? $geo['country'] : '';

        if ($currentCountry !== '' && $currentCountry !== '??' && ! in_array($currentCountry, $knownCountries, true)) {
            $city = isset($geo['city']) ? $geo['city'] : 'unknown city';
            $anomalies['new_country'] = [
                'severity' => 'warning',
                'message'  => "First login from {$currentCountry} ({$city}).",
            ];
        }

        // ── 4. Velocity check ──────────────────────────────────────────────
        $recentLogins = [];
        foreach ($history as $e) {
            if ((time() - $e['time']) < 3600) {
                $recentLogins[] = $e;
            }
        }

        if (count($recentLogins) >= $this->maxLoginsPerHour) {
            $anomalies['high_velocity'] = [
                'severity' => 'warning',
                'message'  => count($recentLogins) . " successful logins in the last hour (threshold: {$this->maxLoginsPerHour}).",
            ];
        }

        // ── 5. Rapid geographic jumps ──────────────────────────────────────
        $last24h = [];
        foreach ($history as $e) {
            if ((time() - $e['time']) < 86400) {
                $last24h[] = $e;
            }
        }
        $countries24h = [];
        foreach ($last24h as $e) {
            $c = isset($e['country']) ? $e['country'] : '';
            if ($c !== '??' && ! in_array($c, $countries24h, true)) {
                $countries24h[] = $c;
            }
        }

        if (count($countries24h) >= 3) {
            $anomalies['geo_jumps'] = [
                'severity' => 'critical',
                'message'  => count($countries24h) . ' different countries in 24 hours: ' . implode(', ', $countries24h),
            ];
        }

        // ── Compute risk score ────────────────────────────────────────────
        $riskScore = 0;
        foreach ($anomalies as $a) {
            $riskScore += match ($a['severity']) {
                'warning'  => 20,
                'critical' => 50,
                default    => 10,
            };
        }
        $riskScore = min(100, $riskScore);

        return [
            'anomalies'  => $anomalies,
            'risk_score' => $riskScore,
        ];
    }

    private function getHistory(mixed $userId): array
    {
        $key = self::HISTORY_KEY . (string) $userId;
        return (array) $this->cache->get($key, []);
    }
}
