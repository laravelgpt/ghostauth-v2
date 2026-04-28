<?php

declare(strict_types=1);

namespace GhostAuth\Mfa;

/**
 * WebAuthnAuthenticator (v2)
 *
 * Passkey / WebAuthn — readonly class, typed constants, PHP 8.3.
 *
 * @package GhostAuth\Mfa
 */
readonly class WebAuthnAuthenticator
{
    public const CHALLENGE_BYTES = 32;
    public const CHALLENGE_TTL   = 300;
    public const ORIGIN_PREFIX   = 'https://';

    public static function createRegistrationChallenge(
        mixed $userId, string $username, string $displayName,
        string $rpId, string $rpName,
    ): array {
        $challenge = random_bytes(self::CHALLENGE_BYTES);
        return [
            'challenge'         => self::b64url($challenge),
            'user_id'           => self::b64url((string) $userId),
            'user_name'         => $username,
            'user_display_name' => $displayName,
            'rp_id'             => $rpId,
            'rp_name'           => $rpName,
            'timeout'           => 60000,
            'algorithms'        => [
                ['type' => 'public-key', 'alg' => -7],
                ['type' => 'public-key', 'alg' => -8],
            ],
            'raw_challenge'     => $challenge,
        ];
    }

    public static function verifyRegistration(
        array $clientDataJson, array $attestationObj,
        string $rawChallenge, string $origin, string $rpId,
    ): array {
        if (($clientDataJson['type'] ?? '') !== 'webauthn.create') {
            throw new \RuntimeException('Invalid clientDataJSON type.');
        }
        if (self::b64urlDecode($clientDataJson['challenge'] ?? '') !== $rawChallenge) {
            throw new \RuntimeException('Challenge mismatch.');
        }
        if (($clientDataJson['origin'] ?? '') !== $origin) {
            throw new \RuntimeException('Origin mismatch.');
        }

        $authData = $attestationObj['authData'] ?? '';
        if (strlen($authData) < 37) {
            throw new \RuntimeException('Invalid authData.');
        }
        if (substr($authData, 0, 32) !== hash('sha256', $rpId, binary: true)) {
            throw new \RuntimeException('RP ID hash mismatch.');
        }

        $flags = ord($authData[32]);
        if (($flags & 0x01) === 0) throw new \RuntimeException('User not present.');
        if (($flags & 0x40) === 0) throw new \RuntimeException('No attested credential.');

        $offset = 37 + 16; // skip rpIdHash + flags + counter + AAGUID
        $credIdLen = (ord($authData[$offset]) << 8) | ord($authData[$offset + 1]);
        $offset += 2;
        $credentialId = substr($authData, $offset, $credIdLen);
        $offset += $credIdLen;

        $coseKey = self::cborDecode(substr($authData, $offset));
        $alg = $coseKey[3] ?? throw new \RuntimeException('Missing COSE algorithm.');

        return [
            'credential_id' => self::b64url($credentialId),
            'public_key'    => self::coseToPem($coseKey, $alg),
            'alg'           => $alg,
            'counter'       => 0,
        ];
    }

    public static function createAuthenticationChallenge(string $rpId): array
    {
        $challenge = random_bytes(self::CHALLENGE_BYTES);
        return [
            'challenge'     => self::b64url($challenge),
            'rp_id'         => $rpId,
            'timeout'       => 60000,
            'raw_challenge' => $challenge,
        ];
    }

    public static function verifyAuthentication(
        array $clientDataJson, array $authenticatorData,
        string $signature, string $rawChallenge,
        string $publicKeyPem, int $alg, string $origin, string $rpId,
    ): array {
        if (($clientDataJson['type'] ?? '') !== 'webauthn.get') {
            throw new \RuntimeException('Invalid clientDataJSON type.');
        }
        if (self::b64urlDecode($clientDataJson['challenge'] ?? '') !== $rawChallenge) {
            throw new \RuntimeException('Challenge mismatch.');
        }
        if (($clientDataJson['origin'] ?? '') !== $origin) {
            throw new \RuntimeException('Origin mismatch.');
        }

        $authBytes = $authenticatorData['raw'] ?? '';
        if (strlen($authBytes) < 37) {
            throw new \RuntimeException('Invalid authenticatorData.');
        }
        if (substr($authBytes, 0, 32) !== hash('sha256', $rpId, binary: true)) {
            throw new \RuntimeException('RP ID hash mismatch.');
        }

        $flags = ord($authBytes[32]);
        if (($flags & 0x01) === 0) throw new \RuntimeException('User not present.');

        $counter = unpack('N', substr($authBytes, 33, 4))[1];
        $clientHash = hash('sha256', $clientDataJson['raw'] ?? '', binary: true);

        if (! self::verifySignature($authBytes . $clientHash, $signature, $publicKeyPem, $alg)) {
            throw new \RuntimeException('Signature verification failed.');
        }

        return ['verified' => true, 'counter' => $counter,
                 'user_present' => ($flags & 0x01) !== 0, 'user_verified' => ($flags & 0x04) !== 0];
    }

    private static function verifySignature(string $data, string $sig, string $pem, int $alg): bool
    {
        return match ($alg) {
            -7 => self::verifyEs256($data, $sig, $pem),
            -8 => self::verifyEdDSA($data, $sig, $pem),
            default => throw new \RuntimeException("Unsupported algorithm: $alg"),
        };
    }

    private static function verifyEs256(string $data, string $sig, string $pem): bool
    {
        if (strlen($sig) !== 64) return false;
        $r = ltrim(substr($sig, 0, 32), "\x00");
        $s = ltrim(substr($sig, 32, 32), "\x00");
        if (ord($r[0] ?? '') & 0x80) $r = "\x00" . $r;
        if (ord($s[0] ?? '') & 0x80) $s = "\x00" . $s;
        $der = "\x30" . chr(strlen($r) + strlen($s) + 4)
            . "\x02" . chr(strlen($r)) . $r
            . "\x02" . chr(strlen($s)) . $s;
        return (bool) openssl_verify($data, $der, $pem, OPENSSL_ALGO_SHA256);
    }

    private static function verifyEdDSA(string $data, string $sig, string $pem): bool
    {
        if (strlen($sig) !== 64) return false;
        $lines = array_filter(explode("\n", $pem));
        $b64 = ''; $inKey = false;
        foreach ($lines as $line) {
            if (str_contains($line, 'BEGIN')) { $inKey = true; continue; }
            if (str_contains($line, 'END')) break;
            if ($inKey) $b64 .= trim($line);
        }
        $raw = base64_decode($b64);
        $pubKey = match (strlen($raw)) {
            32 => $raw,
            44 => substr($raw, 12),
            default => null,
        };
        if ($pubKey === null) return false;
        return sodium_crypto_sign_verify_detached($sig, $data, $pubKey);
    }

    private static function coseToPem(array $coseKey, int $alg): string
    {
        return match ($coseKey[1] ?? null) {
            2 => self::ec2ToPem($coseKey),
            1 => self::okpToPem($coseKey),
            default => throw new \RuntimeException("Unsupported COSE key type."),
        };
    }

    private static function ec2ToPem(array $key): string
    {
        $x = $key[-2] ?? ''; $y = $key[-3] ?? '';
        if (is_string($x) && strlen($x) < 32) $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        if (is_string($y) && strlen($y) < 32) $y = str_pad($y, 32, "\x00", STR_PAD_LEFT);
        $point = "\x04" . $x . $y;
        $oid = hex2bin('06082a8648ce3d030107');
        $algoId = "\x30" . chr(strlen($oid) + 2) . $oid;
        $bs = "\x03" . chr(strlen($point) + 1) . "\x00" . $point;
        $spki = "\x30" . chr(strlen($algoId) + strlen($bs)) . $algoId . $bs;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function okpToPem(array $key): string
    {
        $x = $key[-2] ?? '';
        if (is_string($x) && strlen($x) < 32) $x = str_pad($x, 32, "\x00", STR_PAD_LEFT);
        $oid = hex2bin('06032b6570');
        $algoId = "\x30\x05" . $oid;
        $bs = "\x03" . chr(strlen($x) + 1) . "\x00" . $x;
        $spki = "\x30" . chr(strlen($algoId) + strlen($bs)) . $algoId . $bs;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    // =========================================================================
    // Minimal CBOR decoder
    // =========================================================================

    private static function cborDecode(string $data): mixed
    {
        $result = [];
        self::cborVal($data, 0, $result);
        return $result[0];
    }

    private static function cborVal(string $d, int $o, array &$r): int
    {
        if ($o >= strlen($d)) { $r[0] = null; return $o; }
        $byte = ord($d[$o]);
        $maj = ($byte >> 5) & 0x07;
        $add = $byte & 0x1F;
        $p = $o + 1;
        $v = 0;

        if ($add < 24) {
            $v = $add;
        } elseif ($add === 24) {
            $v = ord($d[$p]); $p++;
        } elseif ($add === 25) {
            $v = unpack('n', substr($d, $p, 2))[1]; $p += 2;
        } elseif ($add === 26) {
            $v = unpack('N', substr($d, $p, 4))[1]; $p += 4;
        } elseif ($add === 27) {
            $v = unpack('J', substr($d, $p, 8))[1]; $p += 8;
        } elseif ($add === 31) {
            throw new \RuntimeException('Indefinite CBOR');
        }

        if ($maj === 0) { $r[0] = $v; return $p; }
        if ($maj === 1) { $r[0] = -1 - $v; return $p; }
        if ($maj === 2) { $r[0] = substr($d, $p, $v); return $p + $v; }
        if ($maj === 3) { $r[0] = substr($d, $p, $v); return $p + $v; }
        if ($maj === 4) return self::cborArr($d, $p, $v, $r);
        if ($maj === 5) return self::cborMap($d, $p, $v, $r);
        if ($maj === 6) { self::cborVal($d, $p, $tmp); $r[0] = $tmp[0]; return $p; }
        if ($maj === 7) {
            $r[0] = match ($v) { 20 => false, 21 => true, default => null };
            return $p;
        }
        throw new \RuntimeException("CBOR major: $maj");
    }

    private static function cborArr(string $d, int $o, int $len, array &$r): int
    {
        $arr = [];
        for ($i = 0; $i < $len; $i++) { $v = []; $o = self::cborVal($d, $o, $v); $arr[] = $v[0]; }
        $r[0] = $arr;
        return $o;
    }

    private static function cborMap(string $d, int $o, int $len, array &$r): int
    {
        $map = [];
        for ($i = 0; $i < $len; $i++) {
            $k = []; $o = self::cborVal($d, $o, $k);
            $v = []; $o = self::cborVal($d, $o, $v);
            $map[$k[0]] = $v[0];
        }
        $r[0] = $map;
        return $o;
    }

    private static function b64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function b64urlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
