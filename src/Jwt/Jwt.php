<?php

namespace Nine\Jwt;

use Nine\Exceptions\InvalidTokenException;

/** @internal JWT parsing and base64url helpers. */
final class Jwt
{
    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if ($decoded === false) {
            throw new InvalidTokenException('malformed token');
        }
        return $decoded;
    }

    /**
     * @return array{header: array<string, mixed>, payload: array<string, mixed>, signingInput: string, signature: string}
     * @throws InvalidTokenException
     */
    public static function decode(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('malformed token');
        }
        $header  = json_decode(self::base64UrlDecode($parts[0]), true);
        $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        if (!is_array($header) || !is_array($payload)) {
            throw new InvalidTokenException('malformed token');
        }
        return [
            'header'       => $header,
            'payload'      => $payload,
            'signingInput' => $parts[0] . '.' . $parts[1],
            'signature'    => self::base64UrlDecode($parts[2]),
        ];
    }

    /**
     * Claims of a JWT without verifying it. Only for tokens received directly from the
     * token endpoint over TLS (ID tokens on the callback); verify everything else.
     *
     * @return array<string, mixed>
     */
    public static function claims(string $token): array
    {
        return self::decode($token)['payload'];
    }
}
