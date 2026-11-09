9in PHP SDK
===========

<img src="docs/img/logo.png" width="160" alt="9in"/>

Official PHP SDK for [9in](https://9in.io): hosted login, OpenID Connect provider and SSO.

- **Sign users in** with the authorization code flow + PKCE (endpoints from OIDC discovery,
  ID tokens verified against your tenant's JWKS, refresh token rotation, logout).
- **Protect your API**: verify access tokens locally with every algorithm of your tenant's
  key library (RS/PS/ES/EdDSA from the JWKS, HS with your API's shared secret), and, in
  hybrid mode, catch revocations at once with cached introspection.
- **Manage users** through the Management API (`/api/v1/*`) with a client-credentials token.
- **Keep users in your own database** with the adapter protocol v2 (`/authenticate`,
  `/user`, `/event`) and timestamped, replay-proof signatures.
- **Receive webhooks** and verify their signature.

Requires PHP 8.1+ with `ext-openssl`, `ext-json` and `ext-curl` (and `ext-sodium`, bundled
with PHP, for EdDSA keys). No other dependencies.

```bash
composer require 9in/php-sdk:^3.0
```

Using Laravel? See [`9in/laravel`](https://github.com/9in-io/laravel) (sign-in, guard, webhooks)
and [`9in/laravel-server`](https://github.com/9in-io/laravel-server) (adapter endpoints).

Upgrading from `ssofy/php-sdk` 2.x? Read [MIGRATION.md](MIGRATION.md).

## Configuration

Every setting can come from the environment. `NINE_*` names are read first, the old
`SSOFY_*` names are still accepted as fallbacks:

| Variable | Fallback | Used for |
|---|---|---|
| `NINE_ISSUER` | `SSOFY_URL` | Your tenant, e.g. `https://acme.9in.io` or your custom login domain |
| `NINE_CLIENT_ID` | `SSOFY_CLIENT_ID` | Application (client) id |
| `NINE_CLIENT_SECRET` | `SSOFY_CLIENT_SECRET` | Confidential applications and the Management API |
| `NINE_REDIRECT_URI` | `SSOFY_REDIRECT_URI` | Callback URL registered for the application |
| `NINE_ADAPTER_SECRET` | `SSOFY_API_SECRET` | Adapter (Connections → User database) signing secret |
| `NINE_WEBHOOK_SECRET` | `SSOFY_WEBHOOK_SECRET` | Webhook endpoint signing secret |

`Nine\Env::get('ISSUER')` returns the value and `Nine\Env::source('ISSUER')` tells you which
variable it came from.

Issuers must use `https://` (`insecure_issuer` otherwise), so a typo cannot send codes,
tokens or client secrets in clear text. Plain http is accepted for `localhost`,
`*.localhost` and loopback addresses. For other development hosts (e.g. `http://auth:8897`
in Docker) set `NINE_ALLOW_INSECURE_ISSUER=true` or pass `allow_insecure_issuer` /
`allowInsecureIssuer`.

## Sign users in

```php
use Nine\OAuth2Client;
use Nine\OAuth2Config;
use Nine\Storage\FileStorage;

$client = new OAuth2Client(OAuth2Config::fromEnv([
    'redirect_uri' => 'https://app.acme.com/callback',
    'state_store'  => new FileStorage('/var/lib/myapp/9in'),   // pending logins (PKCE verifier, nonce)
    // 'scopes'   => ['openid', 'profile', 'email', 'offline_access'],   (default)
    // 'audience' => 'https://api.acme.com',                              access tokens for your API
]));

// GET /login
$login = $client->createAuthorizationUrl(['return_to' => '/dashboard']);   // or ['screen' => 'signup']
header('Location: ' . $login['url']);

// GET /callback
$tokens = $client->handleCallback($_GET);         // checks state + iss, exchanges the code, verifies the ID token
$_SESSION['9in'] = $tokens->toArray();
$user = $tokens->claims();                         // sub, email, name, …
header('Location: ' . ($tokens->returnTo ?? '/'));

// later
$tokens = $client->ensureFresh(\Nine\TokenSet::fromArray($_SESSION['9in']));   // refreshes (and rotates) when needed
$info   = $client->getUserInfo($tokens->accessToken);

// logout
$client->revoke($tokens->refreshToken);
header('Location: ' . $client->logoutUrl($tokens->idToken, 'https://app.acme.com/'));
```

Without a `state_store`, keep `$login['pending']` in the user's session and pass it as the
second argument of `handleCallback()`.

## Protect your API

```php
use Nine\TokenVerifier;
use Nine\Exceptions\InvalidTokenException;
use Nine\Exceptions\InsufficientScopeException;

$verifier = new TokenVerifier('https://acme.9in.io');   // pass a StorageInterface as 3rd argument to share the key cache

try {
    $claims = $verifier->verify($_SERVER['HTTP_AUTHORIZATION'] ?? null, [
        'audience' => 'https://api.acme.com',
        'scope'    => 'orders:read',
    ]);
} catch (InvalidTokenException | InsufficientScopeException $e) {
    http_response_code($e->getStatus());   // 401 / 403
    exit;
}

$claims['sub'];        // user id
$claims['client_id'];  // calling application
```

`Nine\Nine::verifyAccessToken($token, ['issuer' => …])` does the same in one call.

Every algorithm of the console's key library is accepted: RS256/384/512, PS256/384/512,
ES256, ES384 and EdDSA (Ed25519) from your tenant's JWKS. When a key names its `alg`, the
token must use exactly that algorithm. For an API whose tokens are signed with an HMAC
key (HS256/384/512), pass that key's secret: `['secret' => getenv('NINE_API_SECRET')]`.
Only access tokens (`typ: at+jwt`) are accepted, never ID tokens.

### Revocation-aware verification (hybrid)

A JWT stays valid until it expires, even after the user signs out or an admin revokes it.
`HybridTokenVerifier` checks the token locally, asks 9in once (introspection) and caches the
answer until a revocation webhook arrives:

```php
use Nine\HybridTokenVerifier;

$verifier = new HybridTokenVerifier([
    'issuer'       => 'https://acme.9in.io',
    'audience'     => 'https://api.acme.com',
    'clientId'     => $clientId,       // a confidential application, for introspection
    'clientSecret' => $clientSecret,
    'cache'        => $sharedStore,    // any StorageInterface shared by your PHP workers
    // 'mode'     => 'hybrid',         // default; 'local' (no introspection) or 'introspect' (every call)
    // 'cacheTtl' => 300,              // longest an answer is trusted without hearing from 9in
]);

$claims = $verifier->verify($_SERVER['HTTP_AUTHORIZATION'] ?? null, ['scope' => 'orders:read']);

// In your webhook endpoint (subscribe it to token.revoked, session.revoked, user.*):
$verifier->handleEvent($event);
```

- **Opaque access tokens** (`9in_at_…`) are always introspected, and cached in hybrid mode.
- **Cache lifetime:** an answer never outlives the token. A refusal is remembered until
  the token expires (a minute for an opaque token).
- **Eviction:** `token.revoked` evicts by `jti`, `session.revoked` by `sid`, and
  `user.sessions_revoked` / `user.deleted` / `user.updated` / `user.password_changed` by
  user.
- **The cache:** PHP forgets its memory after each request, so give the verifier a
  shared `cache` (the Laravel package uses the Laravel cache). Without one it keeps an
  in-process LRU (`cacheSize`, default 10 000), which only helps long-running workers.
- **Shortcut:** `Nine\Nine::createTokenVerifier()` builds the verifier from NINE_ISSUER,
  NINE_CLIENT_ID and NINE_CLIENT_SECRET.

## Manage users

Create a confidential application, grant it `management:*` scopes in the console, then:

```php
use Nine\ManagementClient;

$nine = new ManagementClient('https://acme.9in.io', $clientId, $clientSecret);   // or ManagementClient::fromEnv()

$user = $nine->createUser(['email' => 'jane@acme.com', 'password' => '…', 'emailVerified' => true]);
$nine->findUserByEmail('jane@acme.com');
$nine->updateUser($user['id'], ['name' => 'Jane Doe', 'metadata' => ['plan' => 'pro']]);
$nine->blockUser($user['id']);
$nine->revokeUserSessions($user['id']);
$nine->importUsers([['email' => 'old@acme.com', 'passwordHash' => '$2y$10$…']]);

// Single-use sign-in link (replaces SSOfy's auth/token)
$link = $nine->createLoginLink($user['id'], ['returnTo' => 'https://app.acme.com/callback', 'ttlSeconds' => 600]);
```

Errors throw `Nine\Exceptions\NineException` with `getError()` (`not_found`,
`identifier_taken`, …) and `getStatus()`.

## Keep users in your own database (adapter v2)

Implement three operations and serve them at the adapter URL you set in the console
(Connections → User database):

```php
use Nine\Adapter\AdapterHandler;
use Nine\Adapter\AdapterInterface;
use Nine\Adapter\AdapterUser;

final class MyUsers implements AdapterInterface
{
    public function authenticate(array $identifier, string $password)
    {
        $row = $this->db->findByLogin($identifier['type'], $identifier['value']);
        if (!$row || !password_verify($password, $row['password'])) {
            return self::INVALID;
        }
        return $row['disabled'] ? self::BLOCKED : $this->toUser($row);
    }

    public function findUser(array $query): ?AdapterUser
    {
        $row = isset($query['id'])
            ? $this->db->findById($query['id'])
            : $this->db->findByLogin($query['identifier']['type'], $query['identifier']['value']);
        return $row ? $this->toUser($row) : null;
    }

    public function onEvent(array $event): void
    {
        if ($event['type'] === 'otp.requested') {
            // deliver $event['data']['code'] to $event['data']['to'] by $event['data']['channel'] (email|sms)
        }
    }

    private function toUser(array $row): AdapterUser
    {
        return new AdapterUser([
            'id' => $row['id'], 'email' => $row['email'], 'email_verified' => true,
            'name' => $row['name'], 'metadata' => ['plan' => $row['plan']],
        ]);
    }
}

// POST /9in/authenticate, /9in/user, /9in/event
$handler = new AdapterHandler(getenv('NINE_ADAPTER_SECRET'), new MyUsers());   // [new, old] during rotation
$handler->handle(
    $_SERVER['REQUEST_METHOD'],
    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),
    getallheaders(),
    file_get_contents('php://input')
)->send();
```

Requests carry `9in-signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "t.METHOD.path.body")>`.
They are rejected when the signature does not match or is more than five minutes old.
Responses are signed over `<path>#<9in-request-id>`, so a response cannot be replayed for
another request. Use `Nine\Signature::sign()` / `verify()` if you build the endpoints yourself.

## Webhooks

```php
use Nine\Webhook;
use Nine\Exceptions\NineException;

try {
    $event = Webhook::verify(
        getenv('NINE_WEBHOOK_SECRET'),
        file_get_contents('php://input'),
        $_SERVER['HTTP_9IN_SIGNATURE'] ?? null,
        parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)
    );
} catch (NineException $e) {
    http_response_code($e->getStatus() ?? 400);
    exit;
}

if ($event['type'] === 'user.created') {
    // $event['data']['user']
}
$hybridVerifier->handleEvent($event);   // token.revoked / session.revoked / user.* evict cached tokens
http_response_code(204);
```

`$event['id']` is the same on every retry and redelivery. To handle each event once, wrap
your handler in `EventDeduplicator` (any `AtomicStorageInterface` store: `MemoryStorage`,
`FileStorage` on one server, or a shared cache bridged to `add()`):

```php
use Nine\EventDeduplicator;
use Nine\Storage\FileStorage;

$outcome = (new EventDeduplicator(new FileStorage('/var/lib/myapp/9in')))->process($event['id'], function () use ($event) {
    // handle the event (an exception releases the id and 9in retries)
});
http_response_code($outcome['status'] === EventDeduplicator::IN_PROGRESS ? 409 : 204);
```

Retries of a processed event are `duplicate` (answer 2xx); a retry that arrives while the
first delivery is still running is `in_progress` (answer 409 and 9in tries again later).

## HTTP and caching

The SDK talks HTTP through `Nine\Http\HttpClientInterface` (default: `CurlHttpClient`,
10 s timeout, no redirects) and caches through `Nine\Storage\StorageInterface`
(`MemoryStorage`, `FileStorage`, `NullStorage`). Bridge both to your framework (PSR-18
client, PSR-16 cache, Laravel cache…) by implementing the interfaces.

## Tests

```bash
composer install
composer test
```

## License

The MIT License (MIT). See [LICENSE](LICENSE). 9in and SSOfy are by [Cubelet Ltd](https://cubelet.co.uk).
