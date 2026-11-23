<?php

namespace Nine;

/**
 * Reads 9in settings from the environment: `NINE_<NAME>`.
 */
final class Env
{
    /**
     * @param string $name Setting name with or without the `NINE_` prefix ("ISSUER" or "NINE_ISSUER").
     * @param mixed  $default
     * @return mixed
     */
    public static function get(string $name, $default = null)
    {
        return self::raw(self::name($name)) ?? $default;
    }

    /**
     * The variable a setting is read from (`NINE_ISSUER` for "ISSUER") when it is set, else null.
     */
    public static function source(string $name): ?string
    {
        $nine = self::name($name);
        return self::raw($nine) !== null ? $nine : null;
    }

    private static function name(string $name): string
    {
        return str_starts_with($name, 'NINE_') ? $name : 'NINE_' . $name;
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
