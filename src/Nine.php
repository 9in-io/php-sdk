<?php

namespace Nine;

use Nine\Http\HttpClientInterface;
use Nine\Storage\StorageInterface;

/**
 * Shortcuts.
 *
 *   $claims = Nine::verifyAccessToken($bearer, ['issuer' => 'https://acme.9in.io', 'audience' => 'https://api.acme.com']);
 */
final class Nine
{
    public const VERSION = '4.0.0';

    /**
     * Same as `verifyAccessToken` in @9in-io/sdk/server.
     *
     * @param array{issuer?: string, audience?: string|string[], scope?: string|string[], secret?: string, clockTolerance?: int, http?: HttpClientInterface, cache?: StorageInterface} $options
     *        issuer defaults to NINE_ISSUER
     * @return array<string, mixed>
     */
    public static function verifyAccessToken(?string $token, array $options = []): array
    {
        $issuer = $options['issuer'] ?? Env::get('ISSUER');
        if (!$issuer) {
            throw new \InvalidArgumentException('issuer is required (or set NINE_ISSUER)');
        }
        $verifier = new TokenVerifier($issuer, $options['http'] ?? null, $options['cache'] ?? null, ['allowInsecureIssuer' => !empty($options['allowInsecureIssuer'])]);
        return $verifier->verify($token, array_intersect_key($options, array_flip(['audience', 'scope', 'clockTolerance', 'secret'])));
    }

    /**
     * Same as `createTokenVerifier` in @9in-io/sdk/server: local, hybrid (default) or
     * introspect verification with a revocation-aware cache. See HybridTokenVerifier.
     *
     * @param array<string, mixed> $options issuer (default NINE_ISSUER), audience, secret, mode,
     *        clientId / clientSecret (default NINE_CLIENT_ID / NINE_CLIENT_SECRET), cacheTtl, cacheSize, cache, http
     */
    public static function createTokenVerifier(array $options = []): HybridTokenVerifier
    {
        $options += array_filter([
            'issuer'       => Env::get('ISSUER'),
            'clientId'     => Env::get('CLIENT_ID'),
            'clientSecret' => Env::get('CLIENT_SECRET'),
        ]);
        return new HybridTokenVerifier($options);
    }
}
