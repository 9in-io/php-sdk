<?php

namespace Nine;

/**
 * Reads 9in settings from the environment.
 *
 * Every setting is read as `NINE_<NAME>` first. Installs migrating from SSOfy can keep
 * their old variables for a while: `SSOFY_<NAME>` (or an explicit legacy name such as
 * `SSOFY_URL` for the issuer) is used when the 9in name is not set.
 */
final class Env
{
    /**
     * 9in name => SSOfy names that are still read as fallbacks, in order.
     */
    public const LEGACY = [
        'NINE_ISSUER'          => ['SSOFY_ISSUER', 'SSOFY_URL'],
        'NINE_CLIENT_ID'       => ['SSOFY_CLIENT_ID'],
        'NINE_CLIENT_SECRET'   => ['SSOFY_CLIENT_SECRET'],
        'NINE_REDIRECT_URI'    => ['SSOFY_REDIRECT_URI'],
        'NINE_ADAPTER_SECRET'  => ['SSOFY_ADAPTER_SECRET', 'SSOFY_API_SECRET'],
        'NINE_WEBHOOK_SECRET'  => ['SSOFY_WEBHOOK_SECRET'],
        'NINE_CACHE_DRIVER'    => ['SSOFY_CACHE_DRIVER'],
        'NINE_CACHE_TTL'       => ['SSOFY_CACHE_TTL'],
    ];

    /**
     * @param string $name Setting name with or without the `NINE_` prefix ("ISSUER" or "NINE_ISSUER").
     * @param mixed  $default
     * @return mixed
     */
    public static function get(string $name, $default = null)
    {
        $nine = str_starts_with($name, 'NINE_') ? $name : 'NINE_' . $name;

        $value = self::raw($nine);
        if ($value !== null) {
            return $value;
        }

        $legacy = self::LEGACY[$nine] ?? ['SSOFY_' . substr($nine, 5)];
        foreach ($legacy as $candidate) {
            $value = self::raw($candidate);
            if ($value !== null) {
                return $value;
            }
        }

        return $default;
    }

    /**
     * Which variable a setting was actually read from (handy for deprecation notices).
     */
    public static function source(string $name): ?string
    {
        $nine = str_starts_with($name, 'NINE_') ? $name : 'NINE_' . $name;
        if (self::raw($nine) !== null) {
            return $nine;
        }
        foreach (self::LEGACY[$nine] ?? ['SSOFY_' . substr($nine, 5)] as $candidate) {
            if (self::raw($candidate) !== null) {
                return $candidate;
            }
        }
        return null;
    }

    private static function raw(string $name): ?string
    {
        if (array_key_exists($name, $_ENV) && $_ENV[$name] !== '') {
            return (string) $_ENV[$name];
        }
        if (array_key_exists($name, $_SERVER) && is_scalar($_SERVER[$name]) && $_SERVER[$name] !== '') {
            return (string) $_SERVER[$name];
        }
        $value = getenv($name);
        return $value === false || $value === '' ? null : $value;
    }
}
