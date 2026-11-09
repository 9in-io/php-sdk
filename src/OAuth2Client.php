<?php

namespace Nine;

use Nine\Exceptions\InvalidStateException;
use Nine\Exceptions\InvalidTokenException;
use Nine\Exceptions\NineException;
use Nine\Jwt\Jwt;

/**
 * OpenID Connect client for server-side applications: authorization code flow with PKCE
 * (S256), endpoints from discovery, ID tokens verified against the tenant's JWKS, refresh
 * token rotation, RP-initiated logout and client-credentials tokens.
 *
 *   $client = new OAuth2Client(OAuth2Config::fromEnv(['state_store' => $store]));
 *
 *   // /login
 *   $login = $client->createAuthorizationUrl(['return_to' => '/dashboard']);
 *   header('Location: ' . $login['url']);
 *
 *   // /callback
 *   $tokens = $client->handleCallback($_GET);
 *   $_SESSION['nine'] = $tokens->toArray();
 *
 * Without a state store, keep `$login['pending']` in the user's session yourself and
 * pass it to handleCallback().
 */
final class OAuth2Client
{
    /** @var OAuth2Config */
    private $config;

    /** @var TokenVerifier */
    private $verifier;

    public function __construct(OAuth2Config $config)
    {
        $this->config   = $config;
        $this->verifier = new TokenVerifier($config->issuer, $config->http, $config->cache, ['allowInsecureIssuer' => $config->allowInsecureIssuer]);
    }

    public function config(): OAuth2Config
    {
        return $this->config;
    }

    /** Verifier for access tokens of the same tenant (for your API routes). */
    public function verifier(): TokenVerifier
    {
        return $this->verifier;
    }

    /**
     * @return array<string, mixed> discovery document
     */
    public function discovery(): array
    {
        return Discovery::fetch($this->config->issuer, $this->config->http, $this->config->cache);
    }

    /**
     * Starts a login.
     *
     * @param array{return_to?: string, prompt?: string, login_hint?: string, screen?: string, redirect_uri?: string, params?: array<string, string>} $options
     *        screen "signup" opens the registration form (prompt=create)
     * @return array{url: string, state: string, pending: array<string, mixed>}
     */
    public function createAuthorizationUrl(array $options = []): array
    {
        $redirectUri = $options['redirect_uri'] ?? $this->config->redirectUri;
        if (!$redirectUri) {
            throw new \InvalidArgumentException('redirect_uri is required');
        }
        $pending = [
            'state'        => Jwt::base64UrlEncode(random_bytes(16)),
            'nonce'        => Jwt::base64UrlEncode(random_bytes(16)),
            'verifier'     => Jwt::base64UrlEncode(random_bytes(48)),
            'redirect_uri' => $redirectUri,
            'return_to'    => $options['return_to'] ?? null,
            'created_at'   => time(),
        ];

        $params = [
            'response_type'         => 'code',
            'client_id'             => $this->config->clientId,
            'redirect_uri'          => $redirectUri,
            'scope'                 => implode(' ', $this->config->scopes),
            'state'                 => $pending['state'],
            'nonce'                 => $pending['nonce'],
            'code_challenge'        => self::codeChallenge($pending['verifier']),
            'code_challenge_method' => 'S256',
        ];
        if ($this->config->audience) {
            $params['audience'] = $this->config->audience;
        }
        if ($this->config->locale) {
            $params['ui_locales'] = $this->config->locale;
        }
        if (!empty($options['login_hint'])) {
            $params['login_hint'] = $options['login_hint'];
        }
        if (($options['screen'] ?? null) === 'signup') {
            $params['prompt'] = 'create';
        } elseif (!empty($options['prompt'])) {
            $params['prompt'] = $options['prompt'];
        }
        $params = array_merge($params, $options['params'] ?? []);

        if ($this->config->stateStore) {
            $this->config->stateStore->put($this->stateKey($pending['state']), json_encode($pending), $this->config->loginTimeout);
        }

        $endpoint = (string) $this->discovery()['authorization_endpoint'];
        $url      = $endpoint . (strpos($endpoint, '?') === false ? '?' : '&') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        return ['url' => $url, 'state' => $pending['state'], 'pending' => $pending];
    }

    /**
     * Completes the login on the callback URL: checks state and issuer, exchanges the code
     * with the PKCE verifier, and verifies the ID token (signature, audience, nonce).
     *
     * @param array<string, mixed>      $query   the callback's query parameters ($_GET)
     * @param array<string, mixed>|null $pending from createAuthorizationUrl() when you keep it yourself
     * @throws InvalidStateException
     * @throws NineException          error returned by 9in (e.g. access_denied, login_required)
     */
    public function handleCallback(array $query, ?array $pending = null): TokenSet
    {
        $state = isset($query['state']) ? (string) $query['state'] : '';
        if ($pending === null && $state !== '' && $this->config->stateStore) {
            $raw = $this->config->stateStore->get($this->stateKey($state));
            $this->config->stateStore->delete($this->stateKey($state));
            $pending = $raw !== null ? json_decode($raw, true) : null;
        }

        if (!empty($query['error'])) {
            throw new NineException((string) $query['error'], isset($query['error_description']) ? (string) $query['error_description'] : null, 400);
        }
        if (empty($query['code'])) {
            throw new NineException('missing_code', 'no authorization code in the callback', 400);
        }
        if (!is_array($pending) || !isset($pending['state']) || !hash_equals((string) $pending['state'], $state)) {
            throw new InvalidStateException();
        }
        if (time() - (int) ($pending['created_at'] ?? 0) > $this->config->loginTimeout) {
            throw new InvalidStateException('login expired');
        }
        $discovery = $this->discovery();
        if (!empty($query['iss']) && rtrim((string) $query['iss'], '/') !== rtrim((string) $discovery['issuer'], '/')) {
            throw new NineException('invalid_issuer', 'unexpected issuer ' . $query['iss'], 400);
        }

        $response = $this->tokenRequest([
            'grant_type'    => 'authorization_code',
            'code'          => (string) $query['code'],
            'redirect_uri'  => (string) $pending['redirect_uri'],
            'code_verifier' => (string) $pending['verifier'],
        ]);
        $tokens           = TokenSet::fromTokenResponse($response);
        $tokens->returnTo = $pending['return_to'] ?? null;

        if ($tokens->idToken) {
            $this->verifier->verifyIdToken($tokens->idToken, $this->config->clientId, (string) $pending['nonce']);
        } elseif (in_array('openid', $this->config->scopes, true)) {
            throw new InvalidTokenException('no ID token in the token response');
        }

        return $tokens;
    }

    /**
     * Exchanges a refresh token (rotated by 9in: store the returned set).
     *
     * @throws NineException invalid_grant when the refresh token was revoked or already used
     */
    public function refresh(TokenSet $tokens): TokenSet
    {
        if (!$tokens->refreshToken) {
            throw new NineException('login_required', 'no refresh token');
        }
        $response = $this->tokenRequest([
            'grant_type'    => 'refresh_token',
            'refresh_token' => $tokens->refreshToken,
        ]);
        return TokenSet::fromTokenResponse($response, $tokens);
    }

    /** Returns $tokens, refreshed when the access token expires within $leewaySeconds. */
    public function ensureFresh(TokenSet $tokens, int $leewaySeconds = 60): TokenSet
    {
        return $tokens->isExpired($leewaySeconds) ? $this->refresh($tokens) : $tokens;
    }

    /**
     * Token for your own back end (client_credentials grant; confidential apps only).
     */
    public function clientCredentials(?string $scope = null, ?string $audience = null): TokenSet
    {
        $form = ['grant_type' => 'client_credentials'];
        if ($scope) {
            $form['scope'] = $scope;
        }
        if ($audience) {
            $form['audience'] = $audience;
        }
        return TokenSet::fromTokenResponse($this->tokenRequest($form));
    }

    /**
     * Fresh claims from the userinfo endpoint.
     *
     * @return array<string, mixed>
     */
    public function getUserInfo(string $accessToken): array
    {
        $response = $this->config->http->request('GET', (string) $this->discovery()['userinfo_endpoint'], [
            'Authorization' => 'Bearer ' . $accessToken,
            'Accept'        => 'application/json',
        ]);
        if (!$response->ok()) {
            $json = $response->json();
            throw new NineException((string) ($json['error'] ?? 'userinfo_failed'), "HTTP {$response->status}", $response->status);
        }
        return $response->json();
    }

    /**
     * Revokes a refresh token (and its rotation family) or an access token. 9in answers 200
     * for tokens that are unknown or already revoked (RFC 7009), so anything else is a real
     * failure (e.g. invalid_client) and throws.
     *
     * @throws NineException
     */
    public function revoke(string $token, string $hint = 'refresh_token'): void
    {
        $endpoint = $this->discovery()['revocation_endpoint'] ?? null;
        if (!$endpoint) {
            return;
        }
        $form     = ['token' => $token, 'token_type_hint' => $hint];
        $headers  = $this->clientAuthHeaders($form);
        $response = $this->config->http->request('POST', (string) $endpoint, $headers, http_build_query($form, '', '&'));
        if (!$response->ok()) {
            $json = $response->json();
            throw new NineException(
                (string) ($json['error'] ?? 'revocation_failed'),
                isset($json['error_description']) ? (string) $json['error_description'] : "HTTP {$response->status}",
                $response->status
            );
        }
    }

    /**
     * URL that ends the 9in session (RP-initiated logout). `$returnTo` must be registered as
     * a logout URL of the application.
     */
    public function logoutUrl(?string $idToken = null, ?string $returnTo = null): string
    {
        $discovery = $this->discovery();
        $endpoint  = (string) ($discovery['end_session_endpoint'] ?? $this->config->issuer . '/oauth/logout');
        $params    = ['client_id' => $this->config->clientId];
        if ($idToken) {
            $params['id_token_hint'] = $idToken;
        }
        if ($returnTo) {
            $params['post_logout_redirect_uri'] = $returnTo;
        }
        return $endpoint . (strpos($endpoint, '?') === false ? '?' : '&') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    public static function codeChallenge(string $verifier): string
    {
        return Jwt::base64UrlEncode(hash('sha256', $verifier, true));
    }

    /**
     * @param array<string, string> $form
     * @return array<string, mixed>
     */
    private function tokenRequest(array $form): array
    {
        $headers  = $this->clientAuthHeaders($form);
        $response = $this->config->http->request('POST', (string) $this->discovery()['token_endpoint'], $headers, http_build_query($form, '', '&'));
        $json     = $response->json();
        if (!$response->ok() || empty($json['access_token'])) {
            throw new NineException(
                (string) ($json['error'] ?? 'request_failed'),
                isset($json['error_description']) ? (string) $json['error_description'] : "HTTP {$response->status}",
                $response->status
            );
        }
        return $json;
    }

    /**
     * client_secret_basic for confidential clients, client_id in the body for public ones.
     *
     * @param array<string, string> $form
     * @return array<string, string>
     */
    private function clientAuthHeaders(array &$form): array
    {
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json'];
        if ($this->config->clientSecret !== null) {
            $headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($this->config->clientId) . ':' . rawurlencode($this->config->clientSecret));
        } else {
            $form['client_id'] = $this->config->clientId;
        }
        return $headers;
    }

    private function stateKey(string $state): string
    {
        return 'nine:login:' . hash('sha256', $state);
    }
}
