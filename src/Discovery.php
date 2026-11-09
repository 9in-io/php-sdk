<?php

namespace Nine;

use Nine\Exceptions\NineException;
use Nine\Http\HttpClientInterface;
use Nine\Storage\StorageInterface;

/**
 * OpenID Connect discovery (`<issuer>/.well-known/openid-configuration`), cached per
 * process and, when a store is given, for five minutes in that store.
 */
final class Discovery
{
    /** @var array<string, array<string, mixed>> */
    private static $memory = [];

    /**
     * @return array<string, mixed>
     */
    public static function fetch(string $issuer, HttpClientInterface $http, ?StorageInterface $cache = null): array
    {
        $issuer = rtrim($issuer, '/');
        if (isset(self::$memory[$issuer])) {
            return self::$memory[$issuer];
        }
        $cacheKey = 'nine:discovery:' . $issuer;
        if ($cache && ($cached = $cache->get($cacheKey)) !== null) {
            $config = json_decode($cached, true);
            if (is_array($config)) {
                return self::$memory[$issuer] = $config;
            }
        }

        $response = $http->request('GET', $issuer . '/.well-known/openid-configuration', ['Accept' => 'application/json']);
        if (!$response->ok()) {
            throw new NineException('discovery_failed', "HTTP {$response->status}", $response->status);
        }
        $config = $response->json();
        if (empty($config['token_endpoint']) || empty($config['jwks_uri'])) {
            throw new NineException('discovery_failed', 'incomplete discovery document');
        }
        if ($cache) {
            $cache->put($cacheKey, json_encode($config), 300);
        }
        return self::$memory[$issuer] = $config;
    }

    /** Clears the per-process cache (tests, long-running workers after a domain change). */
    public static function forget(?string $issuer = null): void
    {
        if ($issuer === null) {
            self::$memory = [];
        } else {
            unset(self::$memory[rtrim($issuer, '/')]);
        }
    }
}
