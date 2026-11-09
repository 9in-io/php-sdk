<?php

namespace Nine\Tests\Support;

use Nine\Jwt\Jwt;

/** A fake 9in tenant: RSA signing key, discovery document and JWKS on a FakeHttpClient. */
final class TestIssuer
{
    public const ISSUER = 'https://acme.9in.test';

    /** @var \OpenSSLAsymmetricKey */
    private $key;

    /** @var string */
    public $kid;

    /** @var FakeHttpClient */
    public $http;

    /** @var array<int, array<string, string>> */
    public $publishedKeys = [];

    public function __construct(?FakeHttpClient $http = null, string $kid = 'key-1')
    {
        $this->http = $http ?? new FakeHttpClient();
        $this->kid  = $kid;
        $this->key  = self::generateKey();
        $this->publish($this->key, $kid);

        $this->http->json('GET', self::ISSUER . '/.well-known/openid-configuration', [
            'issuer'                 => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/oauth/authorize',
            'token_endpoint'         => self::ISSUER . '/oauth/token',
            'userinfo_endpoint'      => self::ISSUER . '/oauth/userinfo',
            'jwks_uri'               => self::ISSUER . '/.well-known/jwks.json',
            'revocation_endpoint'    => self::ISSUER . '/oauth/revoke',
            'end_session_endpoint'   => self::ISSUER . '/oauth/logout',
        ]);
        $this->http->on('GET', self::ISSUER . '/.well-known/jwks.json', function () {
            return new \Nine\Http\Response(200, [], json_encode(['keys' => $this->publishedKeys]));
        });
    }

    public static function generateKey(): \OpenSSLAsymmetricKey
    {
        return openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    }

    public function publish(\OpenSSLAsymmetricKey $key, string $kid): void
    {
        $details               = openssl_pkey_get_details($key);
        $this->publishedKeys[] = [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => Jwt::base64UrlEncode($details['rsa']['n']),
            'e'   => Jwt::base64UrlEncode($details['rsa']['e']),
        ];
    }

    /**
     * @param array<string, mixed> $claims merged over sensible access-token defaults
     * @param array<string, mixed> $header
     */
    public function token(array $claims = [], array $header = [], ?\OpenSSLAsymmetricKey $key = null): string
    {
        $now     = time();
        $payload = array_merge([
            'iss'       => self::ISSUER,
            'sub'       => 'usr_123',
            'aud'       => 'https://api.acme.test',
            'client_id' => 'app_1',
            'scope'     => 'openid orders:read',
            'iat'       => $now,
            'exp'       => $now + 600,
        ], $claims);
        $header  = array_merge(['alg' => 'RS256', 'typ' => 'at+jwt', 'kid' => $this->kid], $header);
        $input   = Jwt::base64UrlEncode(json_encode($header)) . '.' . Jwt::base64UrlEncode(json_encode($payload));
        openssl_sign($input, $signature, $key ?? $this->key, OPENSSL_ALGO_SHA256);
        return $input . '.' . Jwt::base64UrlEncode($signature);
    }
}
