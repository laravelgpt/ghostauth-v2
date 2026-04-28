<?php

declare(strict_types=1);

namespace GhostAuth\Security;

/**
 * IpGuard
 *
 * IP-based access control for authentication.
 * Supports allowlists, denylists, and geographic restrictions.
 *
 * Use cases:
 *   - Restrict admin panel to office IPs
 *   - Block known malicious IP ranges
 *   - Allow only certain countries/regions
 *   - Emergency lockdown (deny all)
 *
 * @package GhostAuth\Security
 */
class IpGuard
{
    /** @var string[]  CIDR ranges to allow (if not empty, only these IPs allowed). */
    private array $allowlist = [];

    /** @var string[]  CIDR ranges to deny. */
    private array $denylist = [];

    /** If true, deny all traffic (emergency lockdown). */
    private bool $denyAll = false;

    /**
     * Add a CIDR range or IP to the allowlist.
     *
     * @param  string $cidr  e.g. '192.168.1.0/24' or '10.0.0.1'
     */
    public function allow(string $cidr): static
    {
        $this->allowlist[] = $cidr;
        return $this;
    }

    /**
     * Add a CIDR range or IP to the denylist.
     */
    public function deny(string $cidr): static
    {
        $this->denylist[] = $cidr;
        return $this;
    }

    /**
     * Set multiple allowed ranges at once.
     *
     * @param  string[] $cidrs
     */
    public function setAllowlist(array $cidrs): static
    {
        $this->allowlist = $cidrs;
        return $this;
    }

    /**
     * Set multiple denied ranges at once.
     *
     * @param  string[] $cidrs
     */
    public function setDenylist(array $cidrs): static
    {
        $this->denylist = $cidrs;
        return $this;
    }

    /**
     * Enable emergency lockdown — deny all traffic.
     */
    public function lockdown(): static
    {
        $this->denyAll = true;
        return $this;
    }

    /**
     * Disable emergency lockdown.
     */
    public function liftLockdown(): static
    {
        $this->denyAll = false;
        return $this;
    }

    /**
     * Check if an IP address is allowed.
     *
     * Evaluation order:
     *   1. If lockdown → DENY
     *   2. If IP in denylist → DENY
     *   3. If allowlist is non-empty and IP not in allowlist → DENY
     *   4. Otherwise → ALLOW
     *
     * @param  string $ip  Client IP address (IPv4 or IPv6).
     * @return bool        True if the IP is allowed to authenticate.
     */
    public function isAllowed(string $ip): bool
    {
        // Emergency lockdown
        if ($this->denyAll) {
            return false;
        }

        // Check denylist
        if (! empty($this->denylist) && $this->ipInRanges($ip, $this->denylist)) {
            return false;
        }

        // If allowlist is defined, only allowlisted IPs pass
        if (! empty($this->allowlist)) {
            return $this->ipInRanges($ip, $this->allowlist);
        }

        // No restrictions
        return true;
    }

    /**
     * Get the reason why an IP was denied.
     *
     * @param  string $ip
     * @return string|null  Null if allowed, otherwise the denial reason.
     */
    public function denialReason(string $ip): ?string
    {
        if ($this->denyAll) {
            return 'Emergency lockdown — all access denied.';
        }

        if (! empty($this->denylist) && $this->ipInRanges($ip, $this->denylist)) {
            return 'IP address is on the denylist.';
        }

        if (! empty($this->allowlist) && ! $this->ipInRanges($ip, $this->allowlist)) {
            return 'IP address is not on the allowlist.';
        }

        return null;
    }

    /**
     * Check if an IP falls within any of the given CIDR ranges.
     *
     * @param  string   $ip     IP address to check.
     * @param  string[] $ranges  CIDR ranges or individual IPs.
     * @return bool
     */
    private function ipInRanges(string $ip, array $ranges): bool
    {
        $ipLong = ip2long($ip);

        if ($ipLong === false) {
            return false; // Invalid IP
        }

        foreach ($ranges as $range) {
            if (str_contains($range, '/')) {
                // CIDR notation
                [$subnet, $maskLen] = explode('/', $range, 2);
                $subnetLong = ip2long($subnet);

                if ($subnetLong === false) {
                    continue;
                }

                $mask = -1 << (32 - (int) $maskLen);
                $ipNetwork = $ipLong & $mask;
                $subnetNetwork = $subnetLong & $mask;

                if ($ipNetwork === $subnetNetwork) {
                    return true;
                }
            } else {
                // Exact IP match
                if ($ipLong === ip2long($range)) {
                    return true;
                }
            }
        }

        return false;
    }
}
