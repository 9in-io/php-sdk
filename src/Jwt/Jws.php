<?php

namespace Nine\Jwt;

use Nine\Exceptions\NineException;

/**
 * @internal JWS signature verification for every algorithm 9in signs with:
 * RS256/384/512, PS256/384/512 (RSA-PSS, salt length = hash length), ES256 (P-256),
 * ES384 (P-384), EdDSA (Ed25519) and HS256/384/512.
 *
 * RSA-PSS is implemented here (EMSA-PSS-VERIFY, RFC 8017 §9.1.2) on top of a raw RSA
 * public-key operation, so it works on every supported PHP version (ext-openssl only got
 * a PSS padding option in PHP 8.5) and enforces the JWS salt length exactly.
 */
final class Jws
{
    public const ASYMMETRIC = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'EdDSA'];
    public const HMAC       = ['HS256' => 'sha256', 'HS384' => 'sha384', 'HS512' => 'sha512'];

    private const HASH = [
        'RS256' => 'sha256', 'RS384' => 'sha384', 'RS512' => 'sha512',
        'PS256' => 'sha256', 'PS384' => 'sha384', 'PS512' => 'sha512',
        'ES256' => 'sha256', 'ES384' => 'sha384',
    ];

    private const OPENSSL_ALGO = ['sha256' => OPENSSL_ALGO_SHA256, 'sha384' => OPENSSL_ALGO_SHA384, 'sha512' => OPENSSL_ALGO_SHA512];

    public static function isSupported(string $alg): bool
    {
        return in_array($alg, self::ASYMMETRIC, true) || isset(self::HMAC[$alg]);
    }

    /**
     * @param array<string, mixed> $jwk public key (asymmetric algorithms)
     */
    public static function verifyWithJwk(string $alg, array $jwk, string $input, string $signature): bool
    {
        if (!Jwk::fits($jwk, $alg)) {
            return false;
        }
        switch ($alg) {
            case 'RS256': case 'RS384': case 'RS512':
                return openssl_verify($input, $signature, Jwk::toPem($jwk), self::OPENSSL_ALGO[self::HASH[$alg]]) === 1;

            case 'PS256': case 'PS384': case 'PS512':
                return self::verifyPss(self::HASH[$alg], Jwk::toPem($jwk), $input, $signature);

            case 'ES256': case 'ES384':
                $size = $alg === 'ES256' ? 32 : 48;
                if (strlen($signature) !== 2 * $size) {
                    return false;
                }
                $der = Jwk::sequence(Jwk::integer(substr($signature, 0, $size)) . Jwk::integer(substr($signature, $size)));
                return openssl_verify($input, $der, Jwk::toPem($jwk), self::OPENSSL_ALGO[self::HASH[$alg]]) === 1;

            case 'EdDSA':
                if (!function_exists('sodium_crypto_sign_verify_detached')) {
                    throw new NineException('unsupported_algorithm', 'EdDSA needs ext-sodium');
                }
                return strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
                    && sodium_crypto_sign_verify_detached($signature, $input, Jwk::ed25519($jwk));
        }
        return false;
    }

    public static function verifyHmac(string $alg, string $secret, string $input, string $signature): bool
    {
        $hash = self::HMAC[$alg] ?? null;
        return $hash !== null && $secret !== '' && hash_equals(hash_hmac($hash, $input, $secret, true), $signature);
    }

    /**
     * RSASSA-PSS verification with MGF1 over the same hash and salt length = hash length.
     */
    private static function verifyPss(string $hash, string $pem, string $input, string $signature): bool
    {
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            return false;
        }
        $details = openssl_pkey_get_details($key);
        $modBits = (int) ($details['bits'] ?? 0);
        $k       = intdiv($modBits + 7, 8);
        if ($modBits < 1024 || strlen($signature) !== $k) {
            return false;
        }

        // s^e mod n
        if (!openssl_public_decrypt($signature, $em, $key, OPENSSL_NO_PADDING)) {
            return false;
        }

        $emBits = $modBits - 1;
        $emLen  = intdiv($emBits + 7, 8);
        $em     = substr(str_pad($em, $k, "\x00", STR_PAD_LEFT), $k - $emLen);
        $hLen   = strlen(hash($hash, '', true));
        $sLen   = $hLen;

        if ($emLen < $hLen + $sLen + 2 || substr($em, -1) !== "\xbc") {
            return false;
        }
        $maskedDb = substr($em, 0, $emLen - $hLen - 1);
        $h        = substr($em, $emLen - $hLen - 1, $hLen);

        $zeroBits = 8 * $emLen - $emBits;
        $topMask  = (0xff << (8 - $zeroBits)) & 0xff;
        if ((ord($maskedDb[0]) & $topMask) !== 0) {
            return false;
        }

        $db    = $maskedDb ^ self::mgf1($hash, $h, $emLen - $hLen - 1);
        $db[0] = chr(ord($db[0]) & (0xff >> $zeroBits));

        $psLen = $emLen - $hLen - $sLen - 2;
        if (substr($db, 0, $psLen) !== str_repeat("\x00", $psLen) || $db[$psLen] !== "\x01") {
            return false;
        }
        $salt = substr($db, -$sLen);

        $mHash = hash($hash, $input, true);
        return hash_equals($h, hash($hash, str_repeat("\x00", 8) . $mHash . $salt, true));
    }

    public static function mgf1(string $hash, string $seed, int $length): string
    {
        $out = '';
        for ($counter = 0; strlen($out) < $length; $counter++) {
            $out .= hash($hash, $seed . pack('N', $counter), true);
        }
        return substr($out, 0, $length);
    }
}
