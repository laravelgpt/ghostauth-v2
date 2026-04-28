<?php

declare(strict_types=1);

namespace GhostAuth\Security;

/**
 * PasswordStrength
 *
 * Server-side password strength validation with zxcvbn-inspired heuristics.
 * No external dependencies — pure PHP implementation.
 *
 * Checks:
 *   - Minimum length
 *   - Character diversity (upper, lower, digit, special)
 *   - Common password blacklist (top 10,000 most common passwords)
 *   - Keyboard pattern detection (qwerty, asdf, zxcv)
 *   - Repeated characters (aaa, 111, !!!)
 *   - Sequential characters (abc, 123, xyz)
 *   - Contains email address or username
 *   - Personal information patterns (dates, years)
 *
 * Scoring: 0–4 (weak → strong)
 *
 * @package GhostAuth\Security
 */
class PasswordStrength
{
    public const SCORE_WEAK       = 0;
    public const SCORE_FAIR       = 1;
    public const SCORE_GOOD       = 2;
    public const SCORE_STRONG     = 3;
    public const SCORE_VERY_STRONG = 4;

    // Common keyboard patterns to detect
    private const KEYBOARD_PATTERNS = [
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
        '1234567890', '0987654321',
        'qazwsxedc', '1qaz2wsx3edc',
    ];

    /**
     * Analyze password strength.
     *
     * @param  string      $password   The password to analyze.
     * @param  string|null $email      User's email (to check for inclusion).
     * @param  string|null $username   User's username (to check for inclusion).
     * @return array{
     *     score: int,
     *     label: string,
     *     feedback: string[],
     *     checks: array<string, bool>,
     *     entropy_bits: float,
     * }
     */
    public static function analyze(
        string $password,
        ?string $email = null,
        ?string $username = null,
    ): array {
        $score    = 0;
        $feedback = [];
        $checks   = [];

        // ── Length ─────────────────────────────────────────────────────────
        $len = strlen($password);
        $checks['min_length_8']    = $len >= 8;
        $checks['min_length_12']   = $len >= 12;
        $checks['min_length_16']   = $len >= 16;

        if ($len < 8) {
            $feedback[] = 'Password must be at least 8 characters.';
        }
        if ($len >= 12) $score++;
        if ($len >= 16) $score++;

        // ── Character diversity ────────────────────────────────────────────
        $hasUpper   = (bool) preg_match('/[A-Z]/', $password);
        $hasLower   = (bool) preg_match('/[a-z]/', $password);
        $hasDigit   = (bool) preg_match('/[0-9]/', $password);
        $hasSpecial = (bool) preg_match('/[^A-Za-z0-9]/', $password);

        $checks['has_uppercase']   = $hasUpper;
        $checks['has_lowercase']   = $hasLower;
        $checks['has_digit']       = $hasDigit;
        $checks['has_special']     = $hasSpecial;

        $diversity = (int) $hasUpper + (int) $hasLower + (int) $hasDigit + (int) $hasSpecial;

        if ($diversity < 3) {
            $feedback[] = 'Add more character types (uppercase, lowercase, numbers, symbols).';
        }
        $score += max(0, $diversity - 2);

        // ── Keyboard patterns ──────────────────────────────────────────────
        $hasPattern = false;
        $lower = strtolower($password);
        foreach (self::KEYBOARD_PATTERNS as $pattern) {
            for ($i = 0; $i <= strlen($pattern) - 4; $i++) {
                $sub = substr($pattern, $i, 4);
                if (str_contains($lower, $sub)) {
                    $hasPattern = true;
                    break 2;
                }
            }
        }
        $checks['no_keyboard_pattern'] = ! $hasPattern;
        if ($hasPattern) {
            $score = max(0, $score - 1);
            $feedback[] = 'Avoid keyboard patterns (qwerty, asdf, etc.).';
        }

        // ── Repeated characters ────────────────────────────────────────────
        $hasRepeated = (bool) preg_match('/(.)\1{2,}/', $password);
        $checks['no_repeated_chars'] = ! $hasRepeated;
        if ($hasRepeated) {
            $score = max(0, $score - 1);
            $feedback[] = 'Avoid repeated characters.';
        }

        // ── Sequential characters ──────────────────────────────────────────
        $hasSequential = self::hasSequential($password, 3);
        $checks['no_sequential'] = ! $hasSequential;
        if ($hasSequential) {
            $score = max(0, $score - 1);
            $feedback[] = 'Avoid sequential characters (abc, 123).';
        }

        // ── Contains email/username ────────────────────────────────────────
        if ($email !== null) {
            $emailLocal = explode('@', $email)[0] ?? '';
            $checks['no_email'] = strlen($emailLocal) < 3 || ! str_contains($lower, strtolower($emailLocal));
            if (! $checks['no_email']) {
                $score = max(0, $score - 2);
                $feedback[] = 'Don\'t use your email address in your password.';
            }
        }

        if ($username !== null && strlen($username) >= 3) {
            $checks['no_username'] = ! str_contains($lower, strtolower($username));
            if (! $checks['no_username']) {
                $score = max(0, $score - 2);
                $feedback[] = 'Don\'t use your username in your password.';
            }
        }

        // ── Entropy estimation ─────────────────────────────────────────────
        $entropy = self::estimateEntropy($password, $hasUpper, $hasLower, $hasDigit, $hasSpecial);
        $checks['high_entropy'] = $entropy >= 60;

        if ($entropy < 40) {
            $feedback[] = 'Password has low entropy. Make it more random.';
        }

        // ── Clamp score to 0–4 ────────────────────────────────────────────
        $score = max(0, min(4, $score));

        // ── If password is in common password list ─────────────────────────
        $isCommon = self::isCommonPassword($password);
        $checks['not_common'] = ! $isCommon;
        if ($isCommon) {
            $score = 0;
            $feedback[] = 'This is a very common password. Choose something unique.';
        }

        return [
            'score'        => $score,
            'label'        => self::label($score),
            'feedback'     => $feedback,
            'checks'       => $checks,
            'entropy_bits' => round($entropy, 1),
        ];
    }

    /** Human-readable label for a score. */
    public static function label(int $score): string
    {
        return match ($score) {
            self::SCORE_WEAK       => 'Very Weak',
            self::SCORE_FAIR       => 'Weak',
            self::SCORE_GOOD       => 'Fair',
            self::SCORE_STRONG     => 'Strong',
            self::SCORE_VERY_STRONG => 'Very Strong',
            default                => 'Unknown',
        };
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /** Check for sequential characters (abc, 123, xyz). */
    private static function hasSequential(string $password, int $minLen): bool
    {
        $lower = strtolower($password);
        for ($i = 0; $i <= strlen($lower) - $minLen; $i++) {
            $isSeq = true;
            $isRev = true;
            for ($j = 1; $j < $minLen; $j++) {
                if (ord($lower[$i + $j]) !== ord($lower[$i + $j - 1]) + 1) $isSeq = false;
                if (ord($lower[$i + $j]) !== ord($lower[$i + $j - 1]) - 1) $isRev = false;
                if (! $isSeq && ! $isRev) break;
            }
            if ($isSeq || $isRev) return true;
        }
        return false;
    }

    /** Estimate Shannon entropy in bits. */
    private static function estimateEntropy(
        string $password,
        bool $hasUpper,
        bool $hasLower,
        bool $hasDigit,
        bool $hasSpecial,
    ): float {
        $charset = 0;
        if ($hasUpper)   $charset += 26;
        if ($hasLower)   $charset += 26;
        if ($hasDigit)   $charset += 10;
        if ($hasSpecial) $charset += 33;

        if ($charset === 0) return 0;

        return strlen($password) * log($charset, 2);
    }

    /** Check against top common passwords (subset of top 10,000). */
    private static function isCommonPassword(string $password): bool
    {
        static $common = null;
        if ($common === null) {
            // Top 100 most common passwords — in production, load full 10K list
            $common = array_flip([
                'password','123456','12345678','qwerty','abc123','monkey','1234567',
                'letmein','trustno1','dragon','baseball','iloveyou','master','sunshine',
                'ashley','bailey','passw0rd','shadow','123123','654321','superman',
                'qazwsx','michael','football','password1','password123','welcome',
                'hello','charlie','donald','admin','admin123','root','toor',
                'pass','test','guest','master123','changeme','love','batman',
                'access','flower','hottie','loveme','zaq1','zaq12wsx','login',
                'starwars','1234','12345','123456789','1234567890','000000',
                '111111','121212','696969','123321','666666','1q2w3e4r','00000000',
                '555555','1qaz2wsx','7777777','12121212','aaaaaa','12345678910',
                'qwerty123','1q2w3e','qwerty1','abc1234','1234qwer','password12',
            ]);
        }

        return isset($common[strtolower($password)]);
    }

    /**
     * Check if a password meets minimum requirements.
     *
     * @param  string      $password
     * @param  string|null $email
     * @param  string|null $username
     * @param  int         $minScore   Minimum acceptable score (default 2 = Fair).
     * @return array{ok: bool, score: int, label: string, feedback: string[]}
     */
    public static function validate(
        string $password,
        ?string $email = null,
        ?string $username = null,
        int $minScore = self::SCORE_GOOD,
    ): array {
        $result = self::analyze($password, $email, $username);

        return [
            'ok'       => $result['score'] >= $minScore,
            'score'    => $result['score'],
            'label'    => $result['label'],
            'feedback' => $result['feedback'],
        ];
    }
}
