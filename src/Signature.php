<?php

namespace Nine;

use Nine\Exceptions\SignatureException;

/**
 * 9in request signatures (adapter protocol v2 and webhooks):
 *
 *   9in-signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<METHOD>.<path>.<raw body>")>
 *
 * The timestamp is part of the signed payload and checked against a tolerance (300 s by
 * default), so a captured request cannot be replayed later. Several `v1=` values and
 * several secrets are accepted to allow secret rotation.
 *
 * Responses from an adapter are signed the same way with the path `<request path>#<9in-request-id>`
 * so a response cannot be replayed for another request.
 */
final class Signature
{
    public const HEADER            = '9in-signature';
    public const REQUEST_ID_HEADER = '9in-request-id';
    public const DEFAULT_TOLERANCE = 300;

    public static function sign(string $secret, string $method, string $path, string $body, ?int $timestamp = null): string
    {
        $timestamp = $timestamp ?? time();
        return 't=' . $timestamp . ',v1=' . self::mac($secret, $timestamp, $method, $path, $body);
    }

    /**
     * @param string|string[] $secret one secret, or several during rotation
     * @return array{ok: bool, reason: string|null, timestamp: int|null}
     *         reason is one of missing | malformed | expired | mismatch
     */
    public static function check($secret, ?string $header, string $method, string $path, string $body, int $toleranceSeconds = self::DEFAULT_TOLERANCE, ?int $now = null): array
    {
        if ($header === null || $header === '') {
            return ['ok' => false, 'reason' => 'missing', 'timestamp' => null];
        }
        $parsed = self::parseHeader($header);
        if ($parsed === null) {
            return ['ok' => false, 'reason' => 'malformed', 'timestamp' => null];
        }
        $now = $now ?? time();
        if (abs($now - $parsed['timestamp']) > $toleranceSeconds) {
            return ['ok' => false, 'reason' => 'expired', 'timestamp' => $parsed['timestamp']];
        }
        foreach ((array) $secret as $candidateSecret) {
            if (!is_string($candidateSecret) || $candidateSecret === '') {
                continue;
            }
            $expected = self::mac($candidateSecret, $parsed['timestamp'], $method, $path, $body);
            foreach ($parsed['v1'] as $candidate) {
                if (hash_equals($expected, $candidate)) {
                    return ['ok' => true, 'reason' => null, 'timestamp' => $parsed['timestamp']];
                }
            }
        }
        return ['ok' => false, 'reason' => 'mismatch', 'timestamp' => $parsed['timestamp']];
    }

    /**
     * @param string|string[] $secret
     */
    public static function verify($secret, ?string $header, string $method, string $path, string $body, int $toleranceSeconds = self::DEFAULT_TOLERANCE, ?int $now = null): bool
    {
        return self::check($secret, $header, $method, $path, $body, $toleranceSeconds, $now)['ok'];
    }

    /**
     * Like verify() but throws.
     *
     * @param string|string[] $secret
     * @throws SignatureException
     */
    public static function assert($secret, ?string $header, string $method, string $path, string $body, int $toleranceSeconds = self::DEFAULT_TOLERANCE, ?int $now = null): int
    {
        $result = self::check($secret, $header, $method, $path, $body, $toleranceSeconds, $now);
        if (!$result['ok']) {
            throw new SignatureException($result['reason']);
        }
        return $result['timestamp'];
    }

    /**
     * @return array{timestamp: int, v1: string[]}|null
     */
    public static function parseHeader(string $header): ?array
    {
        $timestamp = null;
        $v1        = [];
        foreach (explode(',', $header) as $part) {
            $index = strpos($part, '=');
            if ($index === false || $index < 1) {
                return null;
            }
            $name  = trim(substr($part, 0, $index));
            $value = trim(substr($part, $index + 1));
            if ($name === 't') {
                if (!preg_match('/^\d{1,12}$/', $value)) {
                    return null;
                }
                $timestamp = (int) $value;
            } elseif ($name === 'v1') {
                if (!preg_match('/^[0-9a-f]{64}$/', $value)) {
                    return null;
                }
                $v1[] = $value;
            }
        }
        if ($timestamp === null || count($v1) === 0) {
            return null;
        }
        return ['timestamp' => $timestamp, 'v1' => $v1];
    }

    private static function mac(string $secret, int $timestamp, string $method, string $path, string $body): string
    {
        return hash_hmac('sha256', $timestamp . '.' . strtoupper($method) . '.' . $path . '.' . $body, $secret);
    }
}
