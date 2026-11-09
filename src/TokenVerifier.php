<?php

namespace Nine;

use Nine\Exceptions\InsufficientScopeException;
use Nine\Exceptions\InvalidTokenException;
use Nine\Exceptions\NineException;
use Nine\Http\CurlHttpClient;
use Nine\Http\HttpClientInterface;
use Nine\Jwt\Jws;
use Nine\Jwt\Jwt;
use Nine\Storage\StorageInterface;

/**
 * Verifies 9in JWT access tokens locally: signature, token type (`at+jwt`), issuer,
 * audience, expiry and required scopes. No API round trip per request.
 *
 * Every algorithm 9in signs with is accepted: RS256/384/512, PS256/384/512, ES256, ES384
 * and EdDSA against the tenant's JWKS, and HS256/384/512 with your API's shared secret
 * (`secret` option, from the console's key library). When a JWKS key names its `alg`, the
 * token must use exactly that algorithm.
 *
 * Keys are cached for ten minutes (per process, and in `$cache` when given). A token
 * signed with an unknown key id triggers one JWKS refetch (key rotation); unknown key ids
 * are then ignored for a minute so junk tokens cannot make you hammer the JWKS endpoint.
 *
 * This is a local check: a token revoked before it expires still passes. Use
 * HybridTokenVerifier when revocation must take effect at once.
 *
 *   $verifier = new TokenVerifier('https://acme.9in.io');
 *   $claims   = $verifier->verify($bearer, ['audience' => 'https://api.acme.com', 'scope' => 'orders:read']);
 */
final class TokenVerifier
{
    public const ACCESS_TOKEN_TYPES = ['at+jwt', 'application/at+jwt'];

    private const JWKS_TTL      = 600;
    private const MISS_THROTTLE = 60;

    /** @var array<string, array{keys: array<int, array<string, mixed>>, fetchedAt: int}> */
    private static $jwks = [];

    /** @var array<string, int> */
    private static $missingKids = [];

    /** @var string */
    private $issuer;

    /** @var HttpClientInterface */
    private $http;

    /** @var StorageInterface|null */
    private $cache;

    /** @var array<string, mixed> */
    private $defaults;

    /**
     * @param array{audience?: string|string[], scope?: string|string[], clockTolerance?: int, secret?: string, allowInsecureIssuer?: bool} $defaults
     *        secret: the HMAC key your API signs with (HS256/384/512 only);
     *        allowInsecureIssuer accepts a plain-http issuer other than localhost (development only)
     */
    public function __construct(string $issuer, ?HttpClientInterface $http = null, ?StorageInterface $cache = null, array $defaults = [])
    {
        $this->issuer   = Issuer::normalize($issuer, !empty($defaults['allowInsecureIssuer']));
        unset($defaults['allowInsecureIssuer']);
        $this->http     = $http ?? new CurlHttpClient();
        $this->cache    = $cache;
        $this->defaults = $defaults;
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    public function http(): HttpClientInterface
    {
        return $this->http;
    }

    /**
     * @param array{audience?: string|string[], scope?: string|string[], clockTolerance?: int, secret?: string} $options
     * @return array<string, mixed> the token's claims (sub, client_id, scope, aud, exp, jti, sid, …)
     * @throws InvalidTokenException
     * @throws InsufficientScopeException
     */
    public function verify(?string $token, array $options = []): array
    {
        $options = array_merge($this->defaults, $options);
        $token   = self::stripBearer($token);
        if ($token === null || $token === '') {
            throw new InvalidTokenException('missing token');
        }

        $parts = Jwt::decode($token);
        $typ   = strtolower((string) ($parts['header']['typ'] ?? ''));
        if (!in_array($typ, self::ACCESS_TOKEN_TYPES, true)) {
            throw new InvalidTokenException('not an access token');
        }

        $alg = (string) ($parts['header']['alg'] ?? '');
        if (isset(Jws::HMAC[$alg])) {
            $secret = (string) ($options['secret'] ?? '');
            if ($secret === '') {
                throw new InvalidTokenException("HMAC-signed token: pass the API's secret");
            }
            $valid = Jws::verifyHmac($alg, $secret, $parts['signingInput'], $parts['signature']);
        } elseif (in_array($alg, Jws::ASYMMETRIC, true)) {
            $valid = $this->verifyAsymmetric($alg, $parts['header']['kid'] ?? null, $parts['signingInput'], $parts['signature']);
        } else {
            throw new InvalidTokenException('unsupported algorithm');
        }
        if (!$valid) {
            throw new InvalidTokenException('bad signature');
        }

        $this->assertClaims($parts['payload'], $options);

        return $parts['payload'];
    }

    /**
     * Verifies an ID token for `$clientId` (asymmetric signature, issuer, audience, expiry, nonce).
     *
     * @return array<string, mixed>
     * @throws InvalidTokenException
     */
    public function verifyIdToken(string $idToken, string $clientId, ?string $nonce = null, int $clockTolerance = 30): array
    {
        $parts = Jwt::decode($idToken);
        $alg   = (string) ($parts['header']['alg'] ?? '');
        if (!in_array($alg, Jws::ASYMMETRIC, true)) {
            throw new InvalidTokenException('unsupported algorithm');
        }
        if (!$this->verifyAsymmetric($alg, $parts['header']['kid'] ?? null, $parts['signingInput'], $parts['signature'])) {
            throw new InvalidTokenException('bad signature');
        }
        $payload = $parts['payload'];
        $this->assertClaims($payload, ['clockTolerance' => $clockTolerance]);
        if (!in_array($clientId, (array) ($payload['aud'] ?? []), true)) {
            throw new InvalidTokenException('ID token audience mismatch');
        }
        if ($nonce !== null && ($payload['nonce'] ?? null) !== $nonce) {
            throw new InvalidTokenException('ID token nonce mismatch');
        }
        return $payload;
    }

    /**
     * Issuer, expiry/not-before, audience and scope checks on a set of claims (a verified
     * JWT, or an introspection answer for an opaque token).
     *
     * @param array<string, mixed> $claims
     * @param array{audience?: string|string[], scope?: string|string[], clockTolerance?: int} $options
     * @throws InvalidTokenException
     * @throws InsufficientScopeException
     */
    public function checkClaims(array $claims, array $options = []): void
    {
        $this->assertClaims($claims, array_merge($this->defaults, $options));
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     */
    private function assertClaims(array $claims, array $options): void
    {
        $now     = time();
        $skew    = (int) ($options['clockTolerance'] ?? 30);

        if (rtrim((string) ($claims['iss'] ?? ''), '/') !== $this->issuer) {
            throw new InvalidTokenException('issuer mismatch');
        }
        if (!isset($claims['exp']) || !is_numeric($claims['exp']) || $claims['exp'] + $skew < $now) {
            throw new InvalidTokenException('token expired');
        }
        if (isset($claims['nbf']) && is_numeric($claims['nbf']) && $claims['nbf'] - $skew > $now) {
            throw new InvalidTokenException('token not yet valid');
        }
        if (!empty($options['audience'])) {
            $wanted = (array) $options['audience'];
            $aud    = (array) ($claims['aud'] ?? []);
            if (!array_intersect($wanted, $aud)) {
                throw new InvalidTokenException('audience mismatch');
            }
        }
        if (!empty($options['scope'])) {
            $required = is_array($options['scope']) ? $options['scope'] : preg_split('/\s+/', trim($options['scope']));
            $granted  = preg_split('/\s+/', (string) ($claims['scope'] ?? ''));
            $missing  = array_values(array_diff(array_filter($required), $granted));
            if ($missing) {
                throw new InsufficientScopeException('missing ' . implode(', ', $missing));
            }
        }
    }

    public static function stripBearer(?string $token): ?string
    {
        if ($token !== null && stripos($token, 'Bearer ') === 0) {
            return trim(substr($token, 7));
        }
        return $token === null ? null : trim($token);
    }

    /**
     * @param mixed $kid
     */
    private function verifyAsymmetric(string $alg, $kid, string $input, string $signature): bool
    {
        $jwk = $this->findKey($kid);
        if ($jwk === null) {
            throw new InvalidTokenException('unknown signing key');
        }
        // The key decides the algorithm, never the token alone (no algorithm confusion).
        if ((isset($jwk['alg']) && $jwk['alg'] !== $alg) || !\Nine\Jwt\Jwk::fits($jwk, $alg)) {
            throw new InvalidTokenException('algorithm does not match the key');
        }
        try {
            return Jws::verifyWithJwk($alg, $jwk, $input, $signature);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidTokenException('unusable signing key', $e);
        }
    }

    /**
     * @param mixed $kid
     * @return array<string, mixed>|null
     */
    private function findKey($kid): ?array
    {
        foreach ($this->keys(false) as $key) {
            if (($key['kid'] ?? null) === $kid) {
                return $key;
            }
        }
        $missKey  = $this->issuer . '|' . (is_scalar($kid) ? (string) $kid : '');
        $missedAt = self::$missingKids[$missKey] ?? null;
        if ($missedAt !== null && time() - $missedAt < self::MISS_THROTTLE) {
            return null;
        }
        foreach ($this->keys(true) as $key) {
            if (($key['kid'] ?? null) === $kid) {
                return $key;
            }
        }
        self::$missingKids[$missKey] = time();
        if (count(self::$missingKids) > 1000) {
            self::$missingKids = [];
        }
        return null;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function keys(bool $force): array
    {
        $hit = self::$jwks[$this->issuer] ?? null;
        if (!$force && $hit && time() - $hit['fetchedAt'] < self::JWKS_TTL) {
            return $hit['keys'];
        }
        $cacheKey = 'nine:jwks:' . $this->issuer;
        if (!$force && $this->cache && ($cached = $this->cache->get($cacheKey)) !== null) {
            $keys = json_decode($cached, true);
            if (is_array($keys)) {
                self::$jwks[$this->issuer] = ['keys' => $keys, 'fetchedAt' => time()];
                return $keys;
            }
        }

        $config   = Discovery::fetch($this->issuer, $this->http, $this->cache);
        $response = $this->http->request('GET', (string) $config['jwks_uri'], ['Accept' => 'application/json']);
        if (!$response->ok()) {
            throw new NineException('jwks_unavailable', "HTTP {$response->status}", $response->status);
        }
        $keys = $response->json()['keys'] ?? [];
        self::$jwks[$this->issuer] = ['keys' => $keys, 'fetchedAt' => time()];
        if ($this->cache) {
            $this->cache->put($cacheKey, json_encode($keys), self::JWKS_TTL);
        }
        return $keys;
    }

    /** Clears the per-process key cache (tests). */
    public static function forgetKeys(): void
    {
        self::$jwks        = [];
        self::$missingKids = [];
    }
}
