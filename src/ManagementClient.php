<?php

namespace Nine;

use Nine\Exceptions\NineException;
use Nine\Http\CurlHttpClient;
use Nine\Http\HttpClientInterface;
use Nine\Storage\StorageInterface;

/**
 * Management API (`https://<tenant>/api/v1/*`) for one tenant environment. Authenticates
 * with a client-credentials token of a confidential application that was granted
 * `management:*` scopes in the console; the token is cached until shortly before it expires.
 *
 *   $nine = new ManagementClient('https://acme.9in.io', $clientId, $clientSecret);
 *   $user = $nine->createUser(['email' => 'jane@acme.com', 'password' => '…', 'emailVerified' => true]);
 *   $link = $nine->createLoginLink($user['id'], ['returnTo' => 'https://app.acme.com/callback']);
 */
final class ManagementClient
{
    public const SCOPES = 'management:users:read management:users:write management:sessions:write';

    /** @var string */
    private $issuer;

    /** @var OAuth2Client */
    private $oauth;

    /** @var HttpClientInterface */
    private $http;

    /** @var string */
    private $scope;

    /**
     * Tokens by scope. With the default scopes each call asks only for the one it needs, so an
     * application granted some management scopes (not all three) works.
     *
     * @var array<string, TokenSet>
     */
    private $tokens = [];

    /**
     * @param bool $allowInsecureIssuer accept a plain-http issuer other than localhost (development only)
     */
    public function __construct(string $issuer, string $clientId, string $clientSecret, ?HttpClientInterface $http = null, ?StorageInterface $cache = null, string $scope = self::SCOPES, bool $allowInsecureIssuer = false)
    {
        $this->issuer = Issuer::normalize($issuer, $allowInsecureIssuer);
        $this->http   = $http ?? new CurlHttpClient();
        $this->scope  = $scope;
        $this->oauth  = new OAuth2Client(new OAuth2Config([
            'issuer'        => $this->issuer,
            'client_id'     => $clientId,
            'client_secret' => $clientSecret,
            'http'          => $this->http,
            'cache'         => $cache,
            'allow_insecure_issuer' => $allowInsecureIssuer,
        ]));
    }

    /** NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET (SSOFY_* fallbacks). */
    public static function fromEnv(?HttpClientInterface $http = null): self
    {
        return new self((string) Env::get('ISSUER'), (string) Env::get('CLIENT_ID'), (string) Env::get('CLIENT_SECRET'), $http);
    }

    /**
     * @param array{query?: string, cursor?: string, limit?: int} $options
     * @return array{users: array<int, array<string, mixed>>, nextCursor: string|null, total?: int}
     */
    public function listUsers(array $options = []): array
    {
        $params = array_filter([
            'q'      => $options['query'] ?? null,
            'cursor' => $options['cursor'] ?? null,
            'limit'  => $options['limit'] ?? null,
        ]);
        return $this->request('GET', '/users' . ($params ? '?' . http_build_query($params) : ''));
    }

    /**
     * User with identities, sessions, password and MFA status.
     *
     * @return array{user: array<string, mixed>, identities?: array, sessions?: array, hasPassword?: bool, mfa?: array}
     */
    public function getUser(string $id): array
    {
        return $this->request('GET', '/users/' . rawurlencode($id));
    }

    /**
     * @param string $type email | phone | username
     * @return array<string, mixed>|null the user, or null when there is none
     */
    public function findUser(string $type, string $value): ?array
    {
        if (!in_array($type, ['email', 'phone', 'username'], true)) {
            throw new \InvalidArgumentException('type must be email, phone or username');
        }
        try {
            return $this->request('GET', '/users/lookup?' . http_build_query([$type => $value]))['user'];
        } catch (NineException $e) {
            if ($e->getStatus() === 404) {
                return null;
            }
            throw $e;
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    public function findUserByEmail(string $email): ?array
    {
        return $this->findUser('email', $email);
    }

    /**
     * @param array{email?: string, phone?: string, username?: string, password?: string, name?: string, emailVerified?: bool, metadata?: array} $input
     * @return array<string, mixed> the created user
     */
    public function createUser(array $input): array
    {
        return $this->request('POST', '/users', $input)['user'];
    }

    /**
     * Bulk import (up to 500 per call; bcrypt, argon2, PBKDF2 and Firebase scrypt hashes are
     * accepted as `passwordHash`). Records may keep their old `id` and carry `identities`.
     *
     * @param array<int, array<string, mixed>>               $users
     * @param array{onConflict?: string, source?: string}     $options onConflict "skip" (default) or
     *        "update" for users that already exist; source is recorded on `user.imported` events
     * @return array<int, array<string, mixed>> per-row results, in order
     */
    public function importUsers(array $users, array $options = []): array
    {
        $body = ['users' => $users];
        if (!empty($options['onConflict'])) {
            $body['on_conflict'] = (string) $options['onConflict'];
        }
        if (!empty($options['source'])) {
            $body['source'] = (string) $options['source'];
        }
        return $this->request('POST', '/users/import', $body)['results'];
    }

    /**
     * @param array<string, mixed> $input
     * @return array<string, mixed> the updated user
     */
    public function updateUser(string $id, array $input): array
    {
        return $this->request('PATCH', '/users/' . rawurlencode($id), $input)['user'];
    }

    public function deleteUser(string $id): void
    {
        $this->request('DELETE', '/users/' . rawurlencode($id));
    }

    /**
     * @return array<string, mixed>
     */
    public function blockUser(string $id, bool $blocked = true): array
    {
        return $this->updateUser($id, ['blocked' => $blocked]);
    }

    /**
     * Single-use sign-in URL (magic links, handing a signed-in user over from your app).
     * Replaces SSOfy's `auth/token`. `returnTo` must be a registered redirect URL of one of
     * your applications or a path on the login domain. Two-factor authentication still applies.
     *
     * @param array{returnTo?: string, ttlSeconds?: int} $options
     * @return array{url: string, expires_at: int}
     */
    public function createLoginLink(string $userId, array $options = []): array
    {
        $body = [];
        if (!empty($options['returnTo'])) {
            $body['return_to'] = $options['returnTo'];
        }
        if (!empty($options['ttlSeconds'])) {
            $body['ttl_seconds'] = (int) $options['ttlSeconds'];
        }
        return $this->request('POST', '/users/' . rawurlencode($userId) . '/login-link', (object) $body);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function listUserSessions(string $userId): array
    {
        return $this->request('GET', '/users/' . rawurlencode($userId) . '/sessions')['sessions'];
    }

    /** Signs the user out everywhere. Returns the number of sessions revoked. */
    public function revokeUserSessions(string $userId): int
    {
        return (int) $this->request('DELETE', '/users/' . rawurlencode($userId) . '/sessions')['revoked'];
    }

    public function revokeSession(string $sessionId): void
    {
        $this->request('DELETE', '/sessions/' . rawurlencode($sessionId));
    }

    /**
     * @param mixed $body
     * @return array<string, mixed>
     */
    private function request(string $method, string $path, $body = null): array
    {
        $scope   = $this->scopeFor($method, $path);
        $headers = ['Authorization' => 'Bearer ' . $this->accessToken($scope), 'Accept' => 'application/json'];
        $payload = null;
        if ($body !== null) {
            $headers['Content-Type'] = 'application/json';
            $payload                 = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        $response = $this->http->request($method, $this->issuer . '/api/v1' . $path, $headers, $payload);
        if ($response->status === 204) {
            return [];
        }
        $json = $response->json();
        if (!$response->ok()) {
            if ($response->status === 401) {
                unset($this->tokens[$scope]); // revoked or rotated client secret: fetch a new token next time
            }
            throw new NineException(
                (string) ($json['error'] ?? 'request_failed'),
                isset($json['error_description']) ? (string) $json['error_description'] : "HTTP {$response->status}",
                $response->status
            );
        }
        return $json;
    }

    /** The scope a call needs (the configured scope when it was customised). */
    private function scopeFor(string $method, string $path): string
    {
        if ($this->scope !== self::SCOPES) {
            return $this->scope;
        }
        if ($method === 'GET') {
            return 'management:users:read';
        }
        return strpos($path, '/sessions') !== false ? 'management:sessions:write' : 'management:users:write';
    }

    private function accessToken(string $scope): string
    {
        $token = $this->tokens[$scope] ?? null;
        if ($token === null || $token->isExpired(30)) {
            $token = $this->tokens[$scope] = $this->oauth->clientCredentials($scope);
        }
        return $token->accessToken;
    }
}
