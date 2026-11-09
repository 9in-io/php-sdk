<?php

namespace Nine\Jwt;

/** @internal Public JWKs (RSA, EC P-256/P-384, OKP Ed25519) to keys usable by ext-openssl / sodium. */
final class Jwk
{
    private const EC_CURVES = [
        // crv => [curve OID (DER), coordinate length]
        'P-256' => ["\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", 32],
        'P-384' => ["\x06\x05\x2b\x81\x04\x00\x22", 48],
    ];

    /**
     * PEM SubjectPublicKeyInfo for an RSA or EC key.
     *
     * @param array<string, mixed> $jwk
     */
    public static function toPem(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;
        if ($kty === 'RSA') {
            if (empty($jwk['n']) || empty($jwk['e'])) {
                throw new \InvalidArgumentException('RSA key without n/e');
            }
            $modulus  = Jwt::base64UrlDecode((string) $jwk['n']);
            $exponent = Jwt::base64UrlDecode((string) $jwk['e']);

            $key       = self::sequence(self::integer($modulus) . self::integer($exponent));
            $algorithm = self::sequence("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00"); // rsaEncryption, NULL
        } elseif ($kty === 'EC') {
            $curve = self::EC_CURVES[$jwk['crv'] ?? ''] ?? null;
            if ($curve === null || empty($jwk['x']) || empty($jwk['y'])) {
                throw new \InvalidArgumentException('unsupported EC key');
            }
            $x = Jwt::base64UrlDecode((string) $jwk['x']);
            $y = Jwt::base64UrlDecode((string) $jwk['y']);
            if (strlen($x) !== $curve[1] || strlen($y) !== $curve[1]) {
                throw new \InvalidArgumentException('EC coordinates have the wrong length');
            }
            $key       = "\x04" . $x . $y; // uncompressed point
            $algorithm = self::sequence("\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . $curve[0]); // id-ecPublicKey, curve
        } else {
            throw new \InvalidArgumentException('only RSA and EC keys have a PEM form here');
        }

        $spki = self::sequence($algorithm . "\x03" . self::length(strlen($key) + 1) . "\x00" . $key);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Raw 32-byte Ed25519 public key.
     *
     * @param array<string, mixed> $jwk
     */
    public static function ed25519(array $jwk): string
    {
        if (($jwk['kty'] ?? null) !== 'OKP' || ($jwk['crv'] ?? null) !== 'Ed25519' || empty($jwk['x'])) {
            throw new \InvalidArgumentException('not an Ed25519 key');
        }
        $key = Jwt::base64UrlDecode((string) $jwk['x']);
        if (strlen($key) !== 32) {
            throw new \InvalidArgumentException('Ed25519 key has the wrong length');
        }
        return $key;
    }

    /**
     * Whether a JWK can verify `$alg` (key type and curve), independent of its `alg` member.
     *
     * @param array<string, mixed> $jwk
     */
    public static function fits(array $jwk, string $alg): bool
    {
        $kty = $jwk['kty'] ?? null;
        switch ($alg) {
            case 'RS256': case 'RS384': case 'RS512':
            case 'PS256': case 'PS384': case 'PS512':
                return $kty === 'RSA';
            case 'ES256':
                return $kty === 'EC' && ($jwk['crv'] ?? null) === 'P-256';
            case 'ES384':
                return $kty === 'EC' && ($jwk['crv'] ?? null) === 'P-384';
            case 'EdDSA':
                return $kty === 'OKP' && ($jwk['crv'] ?? null) === 'Ed25519';
        }
        return false;
    }

    /** DER length prefix (also used by Jws for ECDSA signatures). */
    public static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    public static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::length(strlen($bytes)) . $bytes;
    }

    public static function sequence(string $contents): string
    {
        return "\x30" . self::length(strlen($contents)) . $contents;
    }
}
