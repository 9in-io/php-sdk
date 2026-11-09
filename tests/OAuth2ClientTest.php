<?php

namespace Nine\Tests;

use Nine\Discovery;
use Nine\Exceptions\InvalidStateException;
use Nine\Exceptions\InvalidTokenException;
use Nine\Exceptions\NineException;
use Nine\Http\Response;
use Nine\OAuth2Client;
use Nine\OAuth2Config;
use Nine\Storage\MemoryStorage;
use Nine\Tests\Support\TestIssuer;
use Nine\TokenSet;
use Nine\TokenVerifier;
use PHPUnit\Framework\TestCase;

final class OAuth2ClientTest extends TestCase
{
    /** @var TestIssuer */
    private $issuer;

    /** @var MemoryStorage */
    private $store;

    /** @var array<string, string> last token request form */
    private $tokenForm = [];

    /** @var string|null nonce to put in the next ID token */
    private $nonce;

    protected function setUp(): void
    {
        Discovery::forget();
        TokenVerifier::forgetKeys();
        $this->issuer = new TestIssuer();
        $this->store  = new MemoryStorage();
        $this->issuer->http->on('POST', TestIssuer::ISSUER . '/oauth/token', function ($url, $headers, $body) {
            parse_str((string) $body, $form);
            $this->tokenForm = $form + ['__auth' => $headers['Authorization'] ?? null];
            if (($form['grant_type'] ?? '') === 'refresh_token' && $form['refresh_token'] === 'rt_revoked') {
                return new Response(400, [], '{"error":"invalid_grant","error_description":"refresh token reused"}');
            }
            return new Response(200, [], json_encode([
                'access_token'  => 'at_' . ($form['grant_type'] ?? ''),
                'token_type'    => 'Bearer',
                'expires_in'    => 900,
                'scope'         => 'openid profile email offline_access',
                'refresh_token' => 'rt_next',
                'id_token'      => $form['grant_type'] === 'authorization_code'
                    ? $this->issuer->token(['aud' => 'app_1', 'nonce' => $this->nonce, 'email' => 'jane@acme.com'])
                    : null,
            ]));
        });
    }

    private function client(array $overrides = []): OAuth2Client
    {
        return new OAuth2Client(new OAuth2Config(array_merge([
            'issuer'        => TestIssuer::ISSUER,
            'client_id'     => 'app_1',
            'client_secret' => 's3cr3t',
            'redirect_uri'  => 'https://app.acme.test/callback',
            'state_store'   => $this->store,
            'http'          => $this->issuer->http,
        ], $overrides)));
    }

    public function testBuildsAPkceAuthorizationUrl(): void
    {
        $login = $this->client(['audience' => 'https://api.acme.test', 'locale' => 'de'])->createAuthorizationUrl(['login_hint' => 'jane@acme.com', 'screen' => 'signup']);
        $this->assertStringStartsWith(TestIssuer::ISSUER . '/oauth/authorize?', $login['url']);
        parse_str((string) parse_url($login['url'], PHP_URL_QUERY), $query);

        $this->assertSame('code', $query['response_type']);
        $this->assertSame('app_1', $query['client_id']);
        $this->assertSame('https://app.acme.test/callback', $query['redirect_uri']);
        $this->assertSame('openid profile email offline_access', $query['scope']);
        $this->assertSame($login['state'], $query['state']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame(OAuth2Client::codeChallenge($login['pending']['verifier']), $query['code_challenge']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43,128}$/', $query['code_challenge']);
        $this->assertSame('create', $query['prompt']);
        $this->assertSame('jane@acme.com', $query['login_hint']);
        $this->assertSame('https://api.acme.test', $query['audience']);
        $this->assertSame('de', $query['ui_locales']);
        $this->assertNotNull($this->store->get('nine:login:' . hash('sha256', $login['state'])));
    }

    public function testPkceChallengeMatchesRfc7636(): void
    {
        // RFC 7636 appendix B
        $this->assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', OAuth2Client::codeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
    }

    public function testCompletesTheCallback(): void
    {
        $client       = $this->client();
        $login        = $client->createAuthorizationUrl(['return_to' => '/dashboard']);
        $this->nonce  = $login['pending']['nonce'];
        $tokens       = $client->handleCallback(['code' => 'c0de', 'state' => $login['state'], 'iss' => TestIssuer::ISSUER]);

        $this->assertSame('at_authorization_code', $tokens->accessToken);
        $this->assertSame('rt_next', $tokens->refreshToken);
        $this->assertSame('/dashboard', $tokens->returnTo);
        $this->assertSame('jane@acme.com', $tokens->claims()['email']);
        $this->assertSame('authorization_code', $this->tokenForm['grant_type']);
        $this->assertSame($login['pending']['verifier'], $this->tokenForm['code_verifier']);
        $this->assertSame('Basic ' . base64_encode('app_1:s3cr3t'), $this->tokenForm['__auth']);
        $this->assertArrayNotHasKey('client_id', $this->tokenForm);

        // state is single-use
        $this->expectException(InvalidStateException::class);
        $client->handleCallback(['code' => 'c0de', 'state' => $login['state']]);
    }

    public function testPublicClientsSendClientIdInTheBody(): void
    {
        $client      = $this->client(['client_secret' => null, 'state_store' => null]);
        $login       = $client->createAuthorizationUrl();
        $this->nonce = $login['pending']['nonce'];
        $client->handleCallback(['code' => 'c', 'state' => $login['state']], $login['pending']);
        $this->assertSame('app_1', $this->tokenForm['client_id']);
        $this->assertNull($this->tokenForm['__auth']);
    }

    public function testRejectsAWrongState(): void
    {
        $client = $this->client();
        $client->createAuthorizationUrl();
        $this->expectException(InvalidStateException::class);
        $client->handleCallback(['code' => 'c', 'state' => 'forged']);
    }

    public function testRejectsANonceMismatch(): void
    {
        $client      = $this->client();
        $login       = $client->createAuthorizationUrl();
        $this->nonce = 'someone-elses-nonce';
        $this->expectException(InvalidTokenException::class);
        $client->handleCallback(['code' => 'c', 'state' => $login['state']]);
    }

    public function testRejectsAMixedUpIssuer(): void
    {
        $client = $this->client();
        $login  = $client->createAuthorizationUrl();
        try {
            $client->handleCallback(['code' => 'c', 'state' => $login['state'], 'iss' => 'https://evil.test']);
            $this->fail('expected invalid_issuer');
        } catch (NineException $e) {
            $this->assertSame('invalid_issuer', $e->getError());
        }
    }

    public function testSurfacesAuthorizationErrors(): void
    {
        $client = $this->client();
        $login  = $client->createAuthorizationUrl();
        try {
            $client->handleCallback(['error' => 'access_denied', 'error_description' => 'user cancelled', 'state' => $login['state']]);
            $this->fail('expected access_denied');
        } catch (NineException $e) {
            $this->assertSame('access_denied', $e->getError());
        }
    }

    public function testRefreshKeepsTheIdTokenAndRotates(): void
    {
        $old       = new TokenSet('at_old', 'id.token.here', 'rt_old', time() - 10, 'openid');
        $refreshed = $this->client()->ensureFresh($old);
        $this->assertSame('at_refresh_token', $refreshed->accessToken);
        $this->assertSame('rt_next', $refreshed->refreshToken);
        $this->assertSame('id.token.here', $refreshed->idToken);
        $this->assertSame('rt_old', $this->tokenForm['refresh_token']);

        $fresh = new TokenSet('at_fresh', null, 'rt', time() + 3600);
        $this->assertSame($fresh, $this->client()->ensureFresh($fresh));
    }

    public function testRefreshFailuresAreInvalidGrant(): void
    {
        try {
            $this->client()->refresh(new TokenSet('at', null, 'rt_revoked', 0));
            $this->fail('expected invalid_grant');
        } catch (NineException $e) {
            $this->assertSame('invalid_grant', $e->getError());
            $this->assertSame(400, $e->getStatus());
        }
    }

    public function testLogoutUrl(): void
    {
        $url = $this->client()->logoutUrl('id.tok', 'https://app.acme.test/');
        $this->assertSame(TestIssuer::ISSUER . '/oauth/logout?client_id=app_1&id_token_hint=id.tok&post_logout_redirect_uri=https%3A%2F%2Fapp.acme.test%2F', $url);
    }

    public function testTokenSetSerialisation(): void
    {
        $set = new TokenSet('a', 'i', 'r', 123, 'openid', '/x');
        $this->assertEquals($set, TokenSet::fromArray($set->toArray()));
    }

    public function testAcceptsTheSsofyUrlKey(): void
    {
        $config = new OAuth2Config(['url' => 'https://login.acme.test/', 'client_id' => 'x']);
        $this->assertSame('https://login.acme.test', $config->issuer);
        $this->assertSame(OAuth2Config::DEFAULT_SCOPES, $config->scopes);
    }
}
