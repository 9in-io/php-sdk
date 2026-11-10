# CHANGELOG

## 4.0.0 - 2026-11-10

Breaking: 9in's webhooks, adapter events and Management API are snake_case throughout, with
ISO 8601 UTC times. Needs the 9in release of 2026-11-10. See [MIGRATION.md](MIGRATION.md).

* `Webhook::verify()` returns `{id, event_type, created_at, tenant, environment, data}` and requires
  `event_type`; `data.userId` is gone (`data.user.id`). The `9in-event-type` header is unchanged.
* `HybridTokenVerifier::handleEvent()` reads `event_type`, `data.token_type` and `data.user.id`.
* `AdapterHandler` requires `event_type` (was `type`) on `/event`; `otp.requested` data is `user_id`,
  `expires_at`.
* `ManagementClient::findUser()` takes `phone_number` (was `phone`); documented shapes use the API's
  snake_case names (`next_cursor`, `has_password`, ISO `expires_at` on login links).

## 3.1.0 - 2026-11-09

* `OAuth2Client::revoke()` throws `NineException` when 9in refuses the revocation (for example
  `invalid_client` with a wrong secret, or a 5xx). It used to ignore the answer, so a failed revocation
  looked successful. Unknown or already revoked tokens still succeed (RFC 7009). `9in/laravel` already
  catches it on logout.
* `ManagementClient::importUsers($users, ['onConflict' => 'update', 'source' => 'auth0'])`: the
  import API's conflict mode and source label (the second argument is optional).

## 3.0.1 - 2026-11-09

Same code as 3.0.0, released again under a new version because the 3.0.0 tag was moved to a
rewritten commit after Packagist had published it (published versions cannot change).

## 3.0.0 - 2026-11-09

Rebranded as **9in** (`9in/php-sdk`, namespace `Nine\`) and moved to the 9in v2 protocol.
See [MIGRATION.md](MIGRATION.md).

* OpenID Connect client with discovery, PKCE S256, ID token verification against JWKS, refresh token rotation, revocation and RP-initiated logout.
* `TokenVerifier`: local access-token verification with every key-library algorithm: RS256/384/512, PS256/384/512 (EMSA-PSS-VERIFY on any PHP ≥ 8.1), ES256, ES384, EdDSA (sodium), HS256/384/512 (`secret`). Requires `typ: at+jwt` and the key's `alg`; JWKS cache that follows key rotation. ID tokens verify with any asymmetric key.
* `HybridTokenVerifier` / `Nine::createTokenVerifier()`: `local`, `hybrid` (default) and `introspect` modes, opaque `9in_at_` tokens, answers cached in a shared `StorageInterface` or an LRU, `handleEvent()` eviction for `token.revoked`, `session.revoked` and `user.*` webhooks.
* `ManagementClient` for `/api/v1/*` with client-credentials tokens, including login links.
* Adapter protocol v2: `AdapterHandler` + `AdapterInterface` for `/authenticate`, `/user` and `/event`.
* `Signature`: timestamped `9in-signature` (`t=…,v1=HMAC-SHA256(t.METHOD.path.body)`), secret rotation, replay window.
* `Webhook::verify()` for tenant webhooks (event list includes `session.revoked` and `token.revoked`).
* `Env`: `NINE_*` variables with `SSOFY_*` fallbacks.
* Issuers must use https (`Issuer::normalize`); http only for localhost, `allow_insecure_issuer` or `NINE_ALLOW_INSECURE_ISSUER`.
* `EventDeduplicator` + `AtomicStorageInterface` (`add()` on Memory/File/Null storage) to process each webhook event once.
* Requires PHP 8.1+; `league/oauth2-client` is no longer needed.
* Removed: `APIClient`, `APIConfig`, the v1 signature classes, repository interfaces for clients/scopes/OTP, and the v1 entities.


## 2.2.1 - 2024-06-17

* Corrected PaginatedResponse namespace and converted to entity. 

## 2.2.0 - 2024-06-16

* Added optional requiredFieldsCheck for BaseModel::export().
* Added "created" property for UserEntity to indicate whether the user is new in find-or-create operations.
* Added filter and sort operations support.
* Updated UserRepositoryInterface::find() signature with filtering support. (Breaking Change)
* Added UserRepositoryInterface::findAll().

## 2.1.1 - 2023-08-05

* Added OAuth2Client::renewAccessToken().
* Renamed: OAuth2Client::deleteState() -> OAuth2Client::destroy().

## 2.1.0 - 2023-07-30

* Config parameter renames.
* Removed ContinueAuthCodeFlow() and introduced handleCallback().
* OAuth2Client methods now throw InvalidState exception.
* Fixes.

## 2.0.2 - 2023-06-22

* Repository contracts have been added to help with resource server integrations.

## 2.0.1 - 2023-06-18

* Hotfix: Handled the refresh token exception.

## 2.0.0 - 2023-06-18

* Renamed the `Client` class to `APIClient` and `ClientConfig` to `APIConfig` for readability. 
* The `OAuth2Config` expects only the `url` parameter be given in config.
The necessary paths for different actions will be appended by the SDK.
* Added the `locale` config parameter to `OAuth2Config`.
* `OAuth2Client::initAuthCodeFlow()` now accepts `uri` which expected to be the full authorization url of auth server 
and `nextUri` which is the next url to be continued after successful authorization.
* Removed `SessionStorage` in accordance to the new workflow which doesn't take responsibility of sessions at SDK level.
* `SignatureValicator` is renamed to `SignatureVerifier` and expects `SignatureGenerator` as a dependency.
* Fixed the token cache invalidation issue.
* Bug Fixes.

## 1.1.9 - 2023-06-01

* Added the missing `username` property in UserEntity.

## 1.1.8 - 2023-05-29

* Added the missing UserEntity properties.

## 1.1.7 - 2023-03-24

* Fixed the minimum stability issue.

## 1.1.6 - 2023-03-19

* Switched to the new User Resource endpoint.

## 1.1.5 - 2023-03-14

* Fixed issues with APIResponse and Token models.

## 1.1.4 - 2023-02-28

* Compliance with Draft 1.30 signature style.

## 1.1.3 - 2023-02-11

* Added missing UserEntity properties.

## 1.1.2 - 2023-02-04

* Added OTPOptionEntity missing properties.
* Fixed nested value normalization with BaseModel::toArray().

## 1.1.1 - 2023-01-24

* Added UserEntity missing properties.
* InvalidValueException hint removed from model constructor.

## 1.1.0 - 2023-01-19

* Moved entities to the respective directory at Models/Entities.
* Added setter/getters to ClientConfig and OAuth2Config classes.
* Added OTPOptionEntity model.
* Added the missed "hash" property to UserEntity model.

## 1.0.0 - 2022-12-16

* First Release.
