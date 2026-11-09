<?php

namespace Nine\Tests\Support;

use Nine\Jwt\Jws;
use Nine\Jwt\Jwt;

/** PHP-native JWS signers for tests (RSA PKCS#1, RSA-PSS, ECDSA, Ed25519, HMAC). */
final class Signers
{
    /**
     * A fresh key for `$alg`: [sign(string $input): string, array $publicJwk].
     *
     * @return array{0: callable, 1: array<string, string>}
     */
    public static function key(string $alg, string $kid = 'k1'): array
    {
        $hash = ['256' => 'sha256', '384' => 'sha384', '512' => 'sha512'][substr($alg, 2)] ?? null;
        switch (substr($alg, 0, 2)) {
            case 'RS':
            case 'PS':
                $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
                $d   = openssl_pkey_get_details($key)['rsa'];
                $jwk = ['kty' => 'RSA', 'n' => Jwt::base64UrlEncode($d['n']), 'e' => Jwt::base64UrlEncode($d['e'])];
                $sign = $alg[0] === 'R'
                    ? function (string $input) use ($key, $hash) {
                        openssl_sign($input, $signature, $key, $hash);
                        return $signature;
                    }
                    : function (string $input) use ($key, $hash) {
                        return self::pssSign($key, $hash, $input);
                    };
                break;
            case 'ES':
                [$curve, $size] = $alg === 'ES256' ? ['prime256v1', 32] : ['secp384r1', 48];
                $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
                $d   = openssl_pkey_get_details($key)['ec'];
                $jwk = [
                    'kty' => 'EC',
                    'crv' => $alg === 'ES256' ? 'P-256' : 'P-384',
                    'x'   => Jwt::base64UrlEncode(str_pad($d['x'], $size, "\x00", STR_PAD_LEFT)),
                    'y'   => Jwt::base64UrlEncode(str_pad($d['y'], $size, "\x00", STR_PAD_LEFT)),
                ];
                $sign = function (string $input) use ($key, $hash, $size) {
                    openssl_sign($input, $der, $key, $hash);
                    return self::derToRaw($der, $size);
                };
                break;
            case 'Ed':
                $pair = sodium_crypto_sign_keypair();
                $jwk  = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Jwt::base64UrlEncode(sodium_crypto_sign_publickey($pair))];
                $sign = function (string $input) use ($pair) {
                    return sodium_crypto_sign_detached($input, sodium_crypto_sign_secretkey($pair));
                };
                break;
            default:
                throw new \InvalidArgumentException($alg);
        }
        return [$sign, $jwk + ['kid' => $kid, 'alg' => $alg, 'use' => 'sig']];
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public static function jwt(callable $sign, array $header, array $claims): string
    {
        $input = Jwt::base64UrlEncode(json_encode($header)) . '.' . Jwt::base64UrlEncode(json_encode($claims));
        return $input . '.' . Jwt::base64UrlEncode($sign($input));
    }

    /**
     * @param array<string, mixed> $claims
     */
    public static function hmac(string $alg, string $secret, array $claims): string
    {
        return self::jwt(function (string $input) use ($alg, $secret) {
            return hash_hmac(Jws::HMAC[$alg], $input, $secret, true);
        }, ['alg' => $alg, 'typ' => 'at+jwt', 'kid' => 'hk'], $claims);
    }

    /** EMSA-PSS-ENCODE (salt = hash length) + raw RSA private operation. */
    private static function pssSign(\OpenSSLAsymmetricKey $key, string $hash, string $input): string
    {
        $modBits = openssl_pkey_get_details($key)['bits'];
        $emBits  = $modBits - 1;
        $emLen   = intdiv($emBits + 7, 8);
        $hLen    = strlen(hash($hash, '', true));
        $salt    = random_bytes($hLen);
        $h       = hash($hash, str_repeat("\x00", 8) . hash($hash, $input, true) . $salt, true);
        $db      = str_repeat("\x00", $emLen - 2 * $hLen - 2) . "\x01" . $salt;
        $masked  = $db ^ Jws::mgf1($hash, $h, $emLen - $hLen - 1);
        $masked[0] = chr(ord($masked[0]) & (0xff >> (8 * $emLen - $emBits)));
        $em      = str_pad($masked . $h . "\xbc", intdiv($modBits + 7, 8), "\x00", STR_PAD_LEFT);
        openssl_private_encrypt($em, $signature, $key, OPENSSL_NO_PADDING);
        return $signature;
    }

    /** DER ECDSA signature → JWS raw r||s. */
    private static function derToRaw(string $der, int $size): string
    {
        $offset = 2 + (ord($der[1]) & 0x80 ? ord($der[1]) & 0x7f : 0);
        $out    = '';
        for ($i = 0; $i < 2; $i++) {
            $length = ord($der[$offset + 1]);
            $int    = ltrim(substr($der, $offset + 2, $length), "\x00");
            $out   .= str_pad($int, $size, "\x00", STR_PAD_LEFT);
            $offset += 2 + $length;
        }
        return $out;
    }
}
