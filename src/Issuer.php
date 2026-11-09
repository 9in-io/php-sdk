<?php

namespace Nine;

use Nine\Exceptions\NineException;

/**
 * Issuer URL validation. Issuers must use https. Plain http is accepted only for
 * localhost, *.localhost and loopback addresses (development), when the caller allows it,
 * or with NINE_ALLOW_INSECURE_ISSUER=true. Query strings, fragments and credentials are
 * rejected.
 */
final class Issuer
{
    /**
     * @return string the issuer without a trailing slash
     * @throws NineException invalid_issuer | insecure_issuer
     */
    public static function normalize(string $issuer, bool $allowInsecure = false): string
    {
        $parts = parse_url($issuer);
        if ($parts === false || empty($parts['scheme']) || empty($parts['host'])) {
            throw new NineException('invalid_issuer', "not a URL: {$issuer}");
        }
        if (isset($parts['query']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            throw new NineException('invalid_issuer', 'an issuer has no query, fragment or credentials');
        }

        $scheme = strtolower($parts['scheme']);
        $secure = $scheme === 'https'
            || ($scheme === 'http' && ($allowInsecure || self::isLocalHost($parts['host']) || self::insecureAllowedByEnv()));
        if (!$secure) {
            throw new NineException('insecure_issuer', "issuer must use https (got {$scheme}://{$parts['host']}); plain http is only accepted for localhost");
        }

        return rtrim($issuer, '/');
    }

    public static function isLocalHost(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));
        return $host === 'localhost'
            || substr($host, -10) === '.localhost'
            || $host === '::1'
            || (bool) preg_match('/^127(\.\d{1,3}){3}$/', $host);
    }

    private static function insecureAllowedByEnv(): bool
    {
        return in_array(strtolower((string) Env::get('ALLOW_INSECURE_ISSUER', '')), ['1', 'true', 'yes', 'on'], true);
    }
}
