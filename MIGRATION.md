# Migrating

## 3.x → 4.x

4.0 follows 9in's move to one wire format (the 9in release of 2026-11-10): snake_case keys
everywhere, the same names going in and coming out, and ISO 8601 UTC strings for times.
Upgrade together with 9in; 3.x cannot read the new webhooks.

| 3.x | 4.x |
|---|---|
| `$event['type']`, `$event['createdAt']` | `$event['event']`, `$event['created_at']` |
| `$event['data']['userId']` | `$event['data']['user']['id']` (for `user.deleted`, the user as it was before the deletion) |
| `token.revoked`: `data.type`, `data.clientId` | `data.token_type`, `data.client_id` |
| `user.login`: `data.client` | `data.client_id` |
| `Webhook::EVENT_TYPE_HEADER` (`9in-event-type`) | `Webhook::EVENT_HEADER` (`9in-event`) |
| Adapter `onEvent`: `$event['type']`, `$event['createdAt']` | `$event['event']`, `$event['created_at']` |
| `otp.requested` `data.userId`, `data.expiresAt` | `data.user_id`, `data.expires_at` |
| `createUser(['emailVerified' => …, 'phone' => …, 'phoneVerified' => …, 'passwordHash' => …])` | `email_verified`, `phone_number`, `phone_number_verified`, `password_hash` (the old names are refused) |
| Import `createdAt`, `lastLoginAt` (ms) | `created_at`, `last_login_at` (ISO 8601 strings) |
| User `createdAt`, `updatedAt`, `lastLoginAt` (ms), `loginCount` | `created_at`, `updated_at`, `last_login_at` (ISO strings), `login_count` |
| `listUsers()['nextCursor']` | `['next_cursor']` |
| `getUser()`: `hasPassword`, `mfa.since`, `mfa.recoveryCodesLeft` | `has_password`, `mfa.enabled_at`, `mfa.recovery_codes_left` |
| Session `userId`, `authTime`, `userAgent`, `createdAt`, `lastSeenAt`, `expiresAt`, `revokedAt` | `user_id`, `auth_time`, `user_agent`, `created_at`, `last_seen_at`, `expires_at` (ISO strings); no `revoked_at` |
| `findUser('phone', …)` | `findUser('phone_number', …)` |
| `createLoginLink()['expires_at']` (Unix seconds) | ISO 8601 string |

`HybridTokenVerifier::handleEvent()` reads the new shape. Method options (`returnTo`,
`ttlSeconds`, `onConflict`) keep their names: they are this library's API.

## From `ssofy/php-sdk` 2.x to `9in/php-sdk` 3.x

SSOfy is now [9in](https://9in.io). 3.0 is a new major version under a new package name
that speaks 9in's v2 protocol: standard OpenID Connect, local JWT verification, the
Management API, adapter protocol v2 and signed webhooks.

**Upgrading is required to use 9in.** `ssofy/php-sdk` 2.x only talks to the SSOfy service (signed API calls to `*.api.ssofy.com` and the 8-endpoint resource server). That service has shut down (ssofy.com has lapsed), and 9in does not serve the SSOfy v1 protocol, so 2.x does not work against 9in. The old versions stay published but are no longer maintained. Move to 3.x as part of moving the app to 9in.
Change the package, the configuration and the calls below in one release.

### 1. Package and namespace

```bash
composer remove ssofy/php-sdk
composer require 9in/php-sdk:^3.0
```

| 2.x | 3.x |
|---|---|
| `SSOfy\…` (PSR-4 root `src/SSOfy`) | `Nine\…` |
| PHP ≥ 5.6, `league/oauth2-client` | PHP ≥ 8.1, no runtime dependencies |

### 2. Configuration

| SSOfy | 9in | Note |
|---|---|---|
| `SSOFY_URL` / `OAuth2Config['url']` | `NINE_ISSUER` / `OAuth2Config['issuer']` | The old name is still read as a fallback; `url` is still accepted as a config key |
| `SSOFY_CLIENT_ID`, `SSOFY_CLIENT_SECRET` | `NINE_CLIENT_ID`, `NINE_CLIENT_SECRET` | Fallbacks kept |
| `SSOFY_API_KEY`, `SSOFY_API_SECRET`, `SSOFY_API_DOMAIN` | removed | The signed API is replaced by local token verification and the Management API |
| `SSOFY_API_SECRET` (resource server) | `NINE_ADAPTER_SECRET` | The adapter secret is a new value from the 9in console; the old name is read as a fallback |
| `pkce_verification`, `pkce_method` | removed | PKCE S256 is always on |
| `scopes` default `[]` / `['*']` | `['openid', 'profile', 'email', 'offline_access']` | `*` is not a 9in scope |

### 3. Sign-in (`OAuth2Client`)

| 2.x | 3.x |
|---|---|
| `initAuthCodeFlow($authorizationUrl, $nextUri)` → `['uri' => …, 'state' => …]` | `createAuthorizationUrl(['return_to' => $nextUri])` → `['url' => …, 'state' => …, 'pending' => …]` |
| `handleCallback($payload)` → state data array with a league `AccessToken` | `handleCallback($_GET)` → `Nine\TokenSet` (ID token verified, `returnTo` set) |
| `getAccessToken($state)` / `renewAccessToken($state)` | `ensureFresh($tokens)` / `refresh($tokens)`; you keep the `TokenSet` (e.g. `$tokens->toArray()` in the session) |
| `getUserInfo($state)` / `refreshUserInfo($state)` | `$tokens->claims()` (ID token) or `getUserInfo($accessToken)` |
| `OAuth2Config::getLogoutUrl()`, `getLogoutEverywhereUrl()` | `logoutUrl($idToken, $returnTo)`; sign out everywhere with `ManagementClient::revokeUserSessions()` |
| `getRegistrationUrl()` | `createAuthorizationUrl(['screen' => 'signup'])` |
| `getProfileUrl()` (`/account`) | Link to `<issuer>/account` |
| `destroy($state)` | Drop the `TokenSet` from your session; `revoke($refreshToken)` |
| `/social/{provider}` URLs | Social buttons are on the hosted login page |

Endpoints come from `<issuer>/.well-known/openid-configuration` (`/oauth/authorize`,
`/oauth/token`, `/oauth/userinfo`, `/oauth/revoke`, `/oauth/logout`) instead of being
hard-coded.

### 4. Token checks (`APIClient`)

`APIClient::verifyAuthentication($token)` and `authenticatedUser($token)` made a signed
call to SSOfy for every token. 3.x verifies the JWT locally:

```php
$claims = (new Nine\TokenVerifier($issuer))->verify($bearer, ['audience' => $api, 'scope' => 'orders:read']);
```

| 2.x | 3.x |
|---|---|
| `APIClient::verifyAuthentication($token)->token` | `TokenVerifier::verify($token)` (claims array) |
| `APIClient::authenticatedUser($token)` | `TokenVerifier::verify()` claims, or `OAuth2Client::getUserInfo()` |
| `APIClient::findUserById($id)` | `ManagementClient::getUser($id)` |
| `invalidateTokenCache()`, `purgeTokenCache()` | `HybridTokenVerifier::handleEvent()` with the `token.revoked` / `session.revoked` webhooks, or `clear()` |
| SSOfy hybrid validation (`TokenValidator` + `token_deleted` event) | `HybridTokenVerifier` (`local` / `hybrid` / `introspect`) + `token.revoked`, `session.revoked`, `user.*` webhooks |
| `InvalidTokenException`, `APIException` | `Nine\Exceptions\InvalidTokenException`, `InsufficientScopeException`, `NineException` |

### 5. Resource server → adapter v2

SSOfy called eight signed endpoints on your server (`client`, `scopes`, `user`, `users`,
`otp-options`, `auth/password`, `auth/token`, `auth/social`, `event`). Applications, scopes,
social login and one-time codes now live in 9in, so three remain:

| SSOfy | 9in adapter v2 |
|---|---|
| `auth/password` | `POST /authenticate` → `AdapterInterface::authenticate()` |
| `user` | `POST /user` → `AdapterInterface::findUser()` |
| `event` | `POST /event` → `AdapterInterface::onEvent()` (`otp.requested` carries the code to deliver) |
| `client`, `scopes` | Configured in the 9in console |
| `otp-options` | Derived from the user's email and phone |
| `auth/social` | Handled by 9in |
| `auth/token` | `ManagementClient::createLoginLink()` |
| `users` (list/filter) | Not needed; `ManagementClient::listUsers()` for 9in-hosted users |
| `ClientRepositoryInterface`, `ScopeRepositoryInterface`, `OTPRepositoryInterface`, `UserRepositoryInterface` | `Nine\Adapter\AdapterInterface` |
| `UserEntity` (`hash`, `display_name`, `phone`, `additional`…) | `Nine\Adapter\AdapterUser` with OIDC names (`phone_number`, `email_verified`, `metadata`…) |

#### Signatures

| SSOfy v1 | 9in v2 |
|---|---|
| Header `Signature: base64(json{hash, salt})` | Header `9in-signature: t=<unix>,v1=<hex>` |
| HMAC over URL path + values concatenated without keys + salt | HMAC over `t.METHOD.path.rawBody` |
| No expiry, payloads with the same values shared a signature | Rejected after 5 minutes; responses bound to the request id |
| `SignatureGenerator`, `SignatureVerifier`, `Models\Signature` | `Nine\Signature::sign()`, `verify()`, `check()`, `assert()` |

### 6. Storage

`Storage\StorageInterface` lost `flushAll()` and `cleanup()` and gained typed signatures
(`put(string, string, int)`). `FileStorage` now stores one hashed file per key with mode
0600 and has its own `cleanup()`. `NullStorage` is unchanged; `MemoryStorage` is new.

### 7. New in 3.x

- `Nine\ManagementClient`: users, sessions, bulk import, login links.
- `Nine\Webhook::verify()`: tenant webhooks (user lifecycle, sign-in, security,
  `session.revoked` and `token.revoked` events).
- Access tokens signed with any key-library algorithm (RS/PS/ES/EdDSA, HS with a shared
  secret), and opaque access tokens through `HybridTokenVerifier`.
- `Nine\Env`: `NINE_*` settings with `SSOFY_*` fallbacks.
