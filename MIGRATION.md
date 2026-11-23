# Migrating

## 4.x → 5.x

The old SSOfy names are gone. If you still set any of them, rename them:

| No longer read | Use |
|---|---|
| `SSOFY_URL`, `SSOFY_ISSUER` | `NINE_ISSUER` |
| `SSOFY_CLIENT_ID`, `SSOFY_CLIENT_SECRET` | `NINE_CLIENT_ID`, `NINE_CLIENT_SECRET` |
| `SSOFY_REDIRECT_URI` | `NINE_REDIRECT_URI` |
| `SSOFY_ADAPTER_SECRET`, `SSOFY_API_SECRET` | `NINE_ADAPTER_SECRET` |
| `SSOFY_WEBHOOK_SECRET` | `NINE_WEBHOOK_SECRET` |
| `SSOFY_<NAME>` | `NINE_<NAME>` |
| `new OAuth2Config(['url' => …])` | `['issuer' => …]` |

`Env::source()` now only reports `NINE_*` names. Nothing else changes.

## 3.x → 4.x

4.0 follows 9in's move to one wire format (the 9in release of 2026-11-10): snake_case keys
everywhere, the same names going in and coming out, and ISO 8601 UTC strings for times.
Upgrade together with 9in; 3.x cannot read the new webhooks.

| 3.x | 4.x |
|---|---|
| `$event['type']`, `$event['createdAt']` | `$event['event_type']`, `$event['created_at']` |
| `$event['data']['userId']` | `$event['data']['user']['id']` (for `user.deleted`, the user as it was before the deletion) |
| `token.revoked`: `data.type`, `data.clientId` | `data.token_type`, `data.client_id` |
| `user.login`: `data.client` | `data.client_id` |
| Adapter `onEvent`: `$event['type']`, `$event['createdAt']` | `$event['event_type']`, `$event['created_at']` |
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
