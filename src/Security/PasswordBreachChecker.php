<?php

declare(strict_types=1);

namespace GhostAuth\Security;

/**
 * PasswordBreachChecker
 *
 * Checks if a password has appeared in known data breaches using the
 * Have I Been Pwned (HIBP) k-anonymity API.
 *
 * How it works (privacy-preserving):
 *   1. SHA-1 hash the plaintext password
 *   2. Send only the first 5 characters of the hash to the API
 *   3. Receive a list of all suffixes + breach counts for matching prefixes
 *   4. Check if the full hash suffix is in the response
 *
 * The full hash is NEVER sent over the network — only a 5-char prefix
 * that could match ~371,000 other hashes. This is k-anonymity.
 *
 * @see https://haveibeenpwned.com/API/v3#PwnedPasswords
 *
 * @package GhostAuth\Security
 */
class PasswordBreachChecker
{
    public const HIBP_API_URL = 'https://api.pwnedpasswords.com/range/';

    /**
     * Check if a password has been seen in breaches.
     *
     * @param  string $plaintext  The plaintext password to check.
     * @param  int    $minBreach  Minimum breach count to consider "breached" (default 1).
     * @return array{
     *     breached: bool,
     *     breach_count: int,
     *     prefix: string,      // First 5 chars of SHA-1 hash.
     * }
     */
    public static function check(string $plaintext, int $minBreach = 1): array
    {
        $hash   = strtoupper(sha1($plaintext));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        // Query HIBP API (only 5-char prefix sent — k-anonymity)
        $ch = curl_init(self::HIBP_API_URL . $prefix);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_USERAGENT      => 'GhostAuth/' . \GhostAuth\GhostAuthConfiguration::VERSION,
        ]);

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            // API unavailable — fail open (don't block legitimate password changes)
            return ['breached' => false, 'breach_count' => 0, 'prefix' => $prefix];
        }

        // Parse response: HASH_SUFFIX:COUNT per line
        $breachCount = 0;
        foreach (explode("\n", (string) $response) as $line) {
            [$remoteSuffix, $count] = explode(':', trim($line)) + ['', '0'];

            if (strtoupper($remoteSuffix) === $suffix) {
                $breachCount = (int) $count;
                break;
            }
        }

        return [
            'breached'     => $breachCount >= $minBreach,
            'breach_count' => $breachCount,
            'prefix'       => $prefix,
        ];
    }

    /**
     * Offline check — verify against a pre-downloaded breach hash file.
     * Useful for air-gapped environments or high-volume validation.
     *
     * @param  string $plaintext   The password to check.
     * @param  string $hashFile    Path to a file containing SHA-1 hashes (one per line).
     * @return array{breached: bool, breach_count: int}
     */
    public static function checkOffline(string $plaintext, string $hashFile): array
    {
        $hash = strtoupper(sha1($plaintext));

        // Stream the file — don't load all hashes into memory
        $handle = fopen($hashFile, 'r');

        if ($handle === false) {
            return ['breached' => false, 'breach_count' => 0];
        }

        $found = false;
        while (($line = fgets($handle, 41)) !== false) {
            if (strtoupper(trim($line)) === $hash) {
                $found = true;
                break;
            }
        }

        fclose($handle);

        return ['breached' => $found, 'breach_count' => $found ? 1 : 0];
    }
}
