<?php

namespace Nine;

use Nine\Http\CurlHttpClient;
use Nine\Http\HttpClientInterface;
use Nine\Storage\StorageInterface;

/**
 * Settings of an application registered in 9in (Applications → your app).
 *
 *   new OAuth2Config([
 *       'issuer'        => 'https://acme.9in.io',   // or your custom login domain
 *       'client_id'     => 'app_…',
 *       'client_secret' => '…',                     // confidential (server-side) apps
 *       'redirect_uri'  => 'https://app.acme.com/callback',
 *       'state_store'   => new FileStorage('/var/lib/myapp/nine'),
 *   ]);
 */
final class OAuth2Config
{
    public const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

    /** @var string */
    public $issuer;

    /** @var string */
    public $clientId;

    /** @var string|null */
    public $clientSecret;

    /** @var string|null */
    public $redirectUri;

    /** @var string[] */
    public $scopes;

    /** @var string|null API identifier to request access tokens for (aud claim) */
    public $audience;

    /** @var string|null language of the hosted pages (ui_locales) */
    public $locale;

    /** @var StorageInterface|null where pending logins (PKCE verifier, nonce) are kept */
    public $stateStore;

    /** @var int seconds a started login stays valid */
    public $loginTimeout;

    /** @var HttpClientInterface */
    public $http;

    /** @var StorageInterface|null discovery document and signing key cache */
    public $cache;

    /** @var bool accept a plain-http issuer other than localhost (development only) */
    public $allowInsecureIssuer;

    /**
     * @param array<string, mixed> $config snake_case keys as documented on the properties
     */
    public function __construct(array $config = [])
    {
        $issuer = $config['issuer'] ?? $config['url'] ?? null; // `url` was the SSOfy name
        if (empty($issuer) || empty($config['client_id'])) {
            throw new \InvalidArgumentException('issuer and client_id are required');
        }
        $this->allowInsecureIssuer = !empty($config['allow_insecure_issuer']);
        $this->issuer       = Issuer::normalize((string) $issuer, $this->allowInsecureIssuer);
        $this->clientId     = (string) $config['client_id'];
        $this->clientSecret = isset($config['client_secret']) && $config['client_secret'] !== '' ? (string) $config['client_secret'] : null;
        $this->redirectUri  = $config['redirect_uri'] ?? null;
        $scopes             = $config['scopes'] ?? self::DEFAULT_SCOPES;
        $this->scopes       = is_string($scopes) ? preg_split('/[\s,]+/', trim($scopes)) : array_values($scopes);
        $this->audience     = $config['audience'] ?? null;
        $this->locale       = $config['locale'] ?? null;
        $this->stateStore   = $config['state_store'] ?? null;
        $this->loginTimeout = (int) ($config['login_timeout'] ?? $config['timeout'] ?? 3600);
        $this->http         = $config['http'] ?? new CurlHttpClient();
        $this->cache        = $config['cache'] ?? null;
    }

    /**
     * Reads NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET, NINE_REDIRECT_URI, NINE_SCOPES,
     * NINE_AUDIENCE (SSOFY_URL / SSOFY_CLIENT_ID / SSOFY_CLIENT_SECRET as fallbacks).
     *
     * @param array<string, mixed> $overrides
     */
    public static function fromEnv(array $overrides = []): self
    {
        return new self(array_merge(array_filter([
            'issuer'        => Env::get('ISSUER'),
            'client_id'     => Env::get('CLIENT_ID'),
            'client_secret' => Env::get('CLIENT_SECRET'),
            'redirect_uri'  => Env::get('REDIRECT_URI'),
            'scopes'        => Env::get('SCOPES'),
            'audience'      => Env::get('AUDIENCE'),
        ], function ($value) {
            return $value !== null;
        }), $overrides));
    }
}
