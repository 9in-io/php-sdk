<?php

namespace Nine;

use Nine\Exceptions\InsufficientScopeException;
use Nine\Exceptions\InvalidTokenException;
use Nine\Exceptions\NineException;
use Nine\Http\CurlHttpClient;
use Nine\Http\HttpClientInterface;
use Nine\Storage\StorageInterface;
use Nine\TokenCache\AnswerCacheInterface;
use Nine\TokenCache\MemoryAnswerCache;
use Nine\TokenCache\StorageAnswerCache;

/**
 * Access-token verification with a choice between speed and revocation, the PHP
 * equivalent of `createTokenVerifier` in @9in-io/sdk:
 *
 * - `hybrid` (default): the local check (TokenVerifier), then one introspection per token.
 *   The answer is cached and dropped when a `token.revoked`, `session.revoked` or user
 *   webhook arrives (pass the events to handleEvent()), or after `cacheTtl` at the latest.
 * - `local`: signature and claims only. Fastest; a revoked token works until it expires.
 * - `introspect`: ask 9in on every call. Always current; one request per call.
 *
 * Opaque tokens (`9in_at_…`) are always introspected (and cached in hybrid mode).
 *
 *   $verifier = new HybridTokenVerifier([
 *       'issuer'       => 'https://acme.9in.io',
 *       'audience'     => 'https://api.acme.com',
 *       'clientId'     => $id,          // a confidential application, for introspection
 *       'clientSecret' => $secret,
 *       'cache'        => $sharedStore, // e.g. Redis/APCu bridged to StorageInterface
 *   ]);
 *   $claims = $verifier->verify($bearer, ['scope' => 'orders:read']);
 *
 *   // webhook endpoint
 *   $verifier->handleEvent(Webhook::verify(…));
 *
 * PHP forgets its memory after each request, so pass a shared `cache` (any
 * StorageInterface: the Laravel bridge, APCu, Redis…). Without one the cache only lives as
 * long as this object, which helps long-running workers but not PHP-FPM.
 */
final class HybridTokenVerifier
{
    public const MODE_LOCAL      = 'local';
    public const MODE_HYBRID     = 'hybrid';
    public const MODE_INTROSPECT = 'introspect';
    public const OPAQUE_PREFIX   = '9in_at_';

    /** Events that make cached answers stale, with the claim they are matched on. */
    public const EVICTING_USER_EVENTS = ['user.sessions_revoked', 'user.deleted', 'user.updated', 'user.password_changed'];

    /** @var string */
    private $mode;

    /** @var TokenVerifier */
    private $local;

    /** @var HttpClientInterface */
    private $http;

    /** @var StorageInterface|null */
    private $storage;

    /** @var AnswerCacheInterface */
    private $answers;

    /** @var string|null */
    private $clientId;

    /** @var string|null */
    private $clientSecret;

    /** @var int seconds */
    private $ttl;

    /**
     * @param array{
     *     issuer: string,
     *     audience?: string|string[],
     *     secret?: string,
     *     clockTolerance?: int,
     *     allowInsecureIssuer?: bool,
     *     mode?: string,
     *     clientId?: string,
     *     clientSecret?: string,
     *     cacheTtl?: int,
     *     cacheSize?: int,
     *     http?: HttpClientInterface,
     *     cache?: StorageInterface
     * } $options
     */
    public function __construct(array $options)
    {
        if (empty($options['issuer'])) {
            throw new \InvalidArgumentException('issuer is required');
        }
        $this->mode = $options['mode'] ?? self::MODE_HYBRID;
        if (!in_array($this->mode, [self::MODE_LOCAL, self::MODE_HYBRID, self::MODE_INTROSPECT], true)) {
            throw new \InvalidArgumentException("unknown mode {$this->mode}");
        }
        $this->clientId     = isset($options['clientId']) && $options['clientId'] !== '' ? (string) $options['clientId'] : null;
        $this->clientSecret = isset($options['clientSecret']) && $options['clientSecret'] !== '' ? (string) $options['clientSecret'] : null;
        if ($this->mode !== self::MODE_LOCAL && ($this->clientId === null || $this->clientSecret === null)) {
            throw new NineException('invalid_options', "{$this->mode} mode needs clientId and clientSecret (a confidential application) for introspection");
        }

        $this->http    = $options['http'] ?? new CurlHttpClient();
        $this->storage = $options['cache'] ?? null;
        $this->ttl     = (int) ($options['cacheTtl'] ?? 300);
        $this->local   = new TokenVerifier((string) $options['issuer'], $this->http, $this->storage, array_filter([
            'audience'            => $options['audience'] ?? null,
            'secret'              => $options['secret'] ?? null,
            'clockTolerance'      => $options['clockTolerance'] ?? null,
            'allowInsecureIssuer' => $options['allowInsecureIssuer'] ?? null,
        ], function ($value) {
            return $value !== null;
        }));
        $this->answers = $this->storage
            ? new StorageAnswerCache($this->storage, $this->ttl)
            : new MemoryAnswerCache((int) ($options['cacheSize'] ?? 10000));
    }

    public function mode(): string
    {
        return $this->mode;
    }

    /** The local verifier (same issuer, audience, secret and key cache). */
    public function localVerifier(): TokenVerifier
    {
        return $this->local;
    }

    /**
     * Verifies a bearer token (JWT or opaque) and returns its claims.
     *
     * @param array{scope?: string|string[]} $options
     * @return array<string, mixed>
     * @throws InvalidTokenException     invalid, expired or revoked
     * @throws InsufficientScopeException
     * @throws NineException             introspection failed (network, credentials)
     */
    public function verify(?string $token, array $options = []): array
    {
        $token = TokenVerifier::stripBearer($token);
        if ($token === null || $token === '') {
            throw new InvalidTokenException('missing token');
        }
        $scope  = isset($options['scope']) ? ['scope' => $options['scope']] : [];
        $opaque = strpos($token, self::OPAQUE_PREFIX) === 0;
        if ($opaque && $this->mode === self::MODE_LOCAL) {
            throw new InvalidTokenException('opaque tokens need hybrid or introspect mode');
        }

        $local = $opaque ? null : $this->local->verify($token, $scope);
        if ($this->mode === self::MODE_LOCAL) {
            return $local;
        }

        $claims = $this->lookup($token, $local);
        if ($claims === null) {
            throw new InvalidTokenException('token revoked');
        }
        if ($local === null) {
            $this->local->checkClaims($claims, $scope);
        }
        return $claims;
    }

    /**
     * Drops cached answers a webhook event makes stale and returns how many:
     * `token.revoked` (access token) by jti, `session.revoked` by sid, and
     * user.sessions_revoked / user.deleted / user.updated / user.password_changed by user.
     *
     * @param array{event_type?: string, data?: array<string, mixed>} $event a verified webhook event
     */
    public function handleEvent(array $event): int
    {
        $type = (string) ($event['event_type'] ?? '');
        $data = isset($event['data']) && is_array($event['data']) ? $event['data'] : [];
        $userId = isset($data['user']) && is_array($data['user']) && isset($data['user']['id']) ? (string) $data['user']['id'] : '';

        if ($type === 'token.revoked' && ($data['token_type'] ?? null) === 'access_token' && !empty($data['jti'])) {
            return $this->answers->evict('jti', (string) $data['jti']);
        }
        if ($type === 'session.revoked' && !empty($data['sid'])) {
            return $this->answers->evict('sid', (string) $data['sid']);
        }
        if (in_array($type, self::EVICTING_USER_EVENTS, true) && $userId !== '') {
            return $this->answers->evict('sub', $userId);
        }
        return 0;
    }

    /** Forgets every cached answer. */
    public function clear(): void
    {
        $this->answers->clear();
    }

    /**
     * The live claims (the token's own for a JWT, once 9in confirms it is active), or null
     * when 9in says it is no longer active.
     *
     * @param array<string, mixed>|null $local
     * @return array<string, mixed>|null
     */
    private function lookup(string $token, ?array $local): ?array
    {
        $key = hash('sha256', $token);
        $now = time();

        if ($this->mode === self::MODE_HYBRID) {
            $hit = $this->answers->get($key);
            if ($hit !== null && $hit['until'] > $now) {
                return $hit['claims'];
            }
        }

        $answer = $this->introspect($token);
        $claims = $answer !== null && $local !== null ? $local : $answer;

        if ($this->mode === self::MODE_HYBRID) {
            $expiry = (int) ($claims['exp'] ?? ($local['exp'] ?? 0));
            // A revoked token never comes back: remember the refusal until it expires.
            $until = $claims !== null ? min($now + $this->ttl, $expiry) : ($expiry > 0 ? $expiry : $now + 60);
            if ($until > $now) {
                $this->answers->put($key, $claims, $until);
            }
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function introspect(string $token): ?array
    {
        $config   = Discovery::fetch($this->local->issuer(), $this->http, $this->storage);
        $endpoint = (string) ($config['introspection_endpoint'] ?? $this->local->issuer() . '/oauth/introspect');
        $response = $this->http->request('POST', $endpoint, [
            'Content-Type'  => 'application/x-www-form-urlencoded',
            'Accept'        => 'application/json',
            'Authorization' => 'Basic ' . base64_encode(rawurlencode((string) $this->clientId) . ':' . rawurlencode((string) $this->clientSecret)),
        ], http_build_query(['token' => $token], '', '&'));

        $json = $response->json();
        if (!$response->ok()) {
            throw new NineException(
                (string) ($json['error'] ?? 'introspection_failed'),
                isset($json['error_description']) ? (string) $json['error_description'] : "HTTP {$response->status}",
                $response->status
            );
        }
        if (($json['active'] ?? false) !== true || ($json['token_type'] ?? null) === 'refresh_token') {
            return null;
        }
        return $json;
    }
}
