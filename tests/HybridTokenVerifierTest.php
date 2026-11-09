<?php

namespace Nine\Tests;

use Nine\Discovery;
use Nine\Exceptions\InsufficientScopeException;
use Nine\Exceptions\InvalidTokenException;
use Nine\Exceptions\NineException;
use Nine\HybridTokenVerifier;
use Nine\Http\Response;
use Nine\Nine;
use Nine\Storage\MemoryStorage;
use Nine\Tests\Support\FakeHttpClient;
use Nine\Tests\Support\Signers;
use Nine\TokenVerifier;
use PHPUnit\Framework\TestCase;

/** Mirrors the createTokenVerifier tests of @9in-io/sdk. */
final class HybridTokenVerifierTest extends TestCase
{
    private const ISSUER = 'https://hybrid.9in.test';

    /** @var FakeHttpClient */
    private $http;

    /** @var callable */
    private $sign;

    /** @var string[] */
    private $introspections = [];

    /** @var callable token => answer */
    private $answers;

    protected function setUp(): void
    {
        Discovery::forget();
        TokenVerifier::forgetKeys();
        [$this->sign, $jwk] = Signers::key('ES256');
        $this->answers = function () {
            return ['active' => true];
        };
        $this->http = (new FakeHttpClient())
            ->json('GET', self::ISSUER . '/.well-known/openid-configuration', [
                'issuer'                 => self::ISSUER,
                'token_endpoint'         => self::ISSUER . '/oauth/token',
                'jwks_uri'               => self::ISSUER . '/.well-known/jwks.json',
                'introspection_endpoint' => self::ISSUER . '/oauth/introspect',
            ])
            ->json('GET', self::ISSUER . '/.well-known/jwks.json', ['keys' => [$jwk]])
            ->on('POST', self::ISSUER . '/oauth/introspect', function ($url, $headers, $body) {
                $this->assertSame('Basic ' . base64_encode('api:secret'), $headers['Authorization']);
                parse_str((string) $body, $form);
                $this->introspections[] = $form['token'];
                return new Response(200, [], json_encode(($this->answers)($form['token'])));
            });
    }

    /**
     * @param array<string, mixed> $extra
     * @return array<string, mixed>
     */
    private function claims(array $extra = []): array
    {
        $now = time();
        return array_merge(['iss' => self::ISSUER, 'sub' => 'usr_1', 'aud' => 'https://api.acme.test', 'client_id' => 'app_1', 'scope' => 'orders:read', 'sid' => 'sid_1', 'iat' => $now, 'exp' => $now + 300, 'jti' => 'j1'], $extra);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function token(array $claims): string
    {
        return Signers::jwt($this->sign, ['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => 'k1'], $claims);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function verifier(array $options = []): HybridTokenVerifier
    {
        return new HybridTokenVerifier(array_merge([
            'issuer'       => self::ISSUER,
            'audience'     => 'https://api.acme.test',
            'clientId'     => 'api',
            'clientSecret' => 'secret',
            'http'         => $this->http,
        ], $options));
    }

    public function testIntrospectsOnceServesFromCacheAndDropsTheAnswerOnTokenRevoked(): void
    {
        $revoked       = [];
        $this->answers = function ($token) use (&$revoked) {
            return in_array($token, $revoked, true) ? ['active' => false] : ['active' => true] + $this->claims();
        };
        $verifier = $this->verifier();
        $token    = $this->token($this->claims());

        $this->assertSame('usr_1', $verifier->verify($token, ['scope' => 'orders:read'])['sub']);
        $verifier->verify($token);
        $this->assertCount(1, $this->introspections);
        try {
            $verifier->verify($token, ['scope' => 'admin']);
            $this->fail('expected insufficient_scope');
        } catch (InsufficientScopeException $e) {
        }

        $revoked[] = $token;
        $this->assertSame(0, $verifier->handleEvent(['type' => 'token.revoked', 'data' => ['type' => 'refresh_token', 'sid' => 'sid_1']]));
        $this->assertSame(1, $verifier->handleEvent(['type' => 'token.revoked', 'data' => ['type' => 'access_token', 'jti' => 'j1']]));
        foreach ([1, 2] as $attempt) {
            try {
                $verifier->verify($token);
                $this->fail('expected a revoked token');
            } catch (InvalidTokenException $e) {
                $this->assertStringContainsString('revoked', $e->getMessage());
            }
        }
        $this->assertCount(2, $this->introspections); // the refusal is remembered
    }

    public function testEvictsBySessionAndByUser(): void
    {
        $verifier = $this->verifier();
        $a        = $this->token($this->claims(['jti' => 'a']));
        $b        = $this->token($this->claims(['jti' => 'b', 'sid' => 'sid_2']));
        $verifier->verify($a);
        $verifier->verify($b);
        $this->assertSame(1, $verifier->handleEvent(['type' => 'session.revoked', 'data' => ['sid' => 'sid_2', 'userId' => 'usr_1']]));
        $this->assertSame(1, $verifier->handleEvent(['type' => 'user.sessions_revoked', 'data' => ['userId' => 'usr_1', 'count' => 1]]));
        $this->assertSame(0, $verifier->handleEvent(['type' => 'user.login', 'data' => ['userId' => 'usr_1']]));
        $verifier->verify($a);
        $this->assertCount(3, $this->introspections);

        foreach (['user.deleted', 'user.updated', 'user.password_changed'] as $type) {
            $this->assertSame(1, $verifier->handleEvent(['type' => $type, 'data' => ['userId' => 'usr_1']]), $type);
            $verifier->verify($a);
        }
    }

    public function testCachesTheTokensOwnClaimsNotTheIntrospectionEcho(): void
    {
        $this->answers = function () {
            return ['active' => true, 'sub' => 'someone-else', 'scope' => 'admin'];
        };
        $claims = $this->verifier()->verify($this->token($this->claims()));
        $this->assertSame('usr_1', $claims['sub']);
        $this->assertSame('orders:read', $claims['scope']);
    }

    public function testIntrospectsOpaqueTokensAndChecksTheirAudience(): void
    {
        $this->answers = function ($token) {
            return $token === '9in_at_good'
                ? ['active' => true, 'token_type' => 'access_token'] + $this->claims()
                : ['active' => true] + $this->claims(['aud' => 'https://other']);
        };
        $verifier = $this->verifier();
        $this->assertSame('sid_1', $verifier->verify('9in_at_good')['sid']);
        try {
            $verifier->verify('9in_at_other');
            $this->fail('expected an audience mismatch');
        } catch (InvalidTokenException $e) {
            $this->assertStringContainsString('audience', $e->getMessage());
        }
        $this->assertSame(['9in_at_good', '9in_at_other'], $this->introspections);

        $this->expectExceptionMessage('opaque');
        $this->verifier(['mode' => 'local'])->verify('9in_at_good');
    }

    public function testRefreshTokensAreNotAccessTokens(): void
    {
        $this->answers = function () {
            return ['active' => true, 'token_type' => 'refresh_token'] + $this->claims();
        };
        $this->expectExceptionMessage('revoked');
        $this->verifier()->verify('9in_at_actually_a_refresh_token');
    }

    public function testOpaqueRefusalsWithoutExpiryAreCachedForAMinute(): void
    {
        $this->answers = function () {
            return ['active' => false];
        };
        $storage  = new MemoryStorage();
        $verifier = $this->verifier(['cache' => $storage]);
        foreach ([1, 2] as $attempt) {
            try {
                $verifier->verify('9in_at_dead');
            } catch (InvalidTokenException $e) {
            }
        }
        $this->assertCount(1, $this->introspections);
    }

    public function testSupportsLocalAndIntrospectModes(): void
    {
        $this->answers = function () {
            return ['active' => true] + $this->claims();
        };
        $token = $this->token($this->claims());
        (new HybridTokenVerifier(['issuer' => self::ISSUER, 'http' => $this->http, 'mode' => 'local']))->verify($token);
        $this->assertCount(0, $this->introspections);

        $strict = $this->verifier(['mode' => 'introspect']);
        $strict->verify($token);
        $strict->verify($token);
        $this->assertCount(2, $this->introspections);

        $this->expectExceptionMessage('clientId and clientSecret');
        new HybridTokenVerifier(['issuer' => self::ISSUER]);
    }

    public function testASharedStoreServesAndEvictsAcrossInstances(): void
    {
        $shared = new MemoryStorage();
        $token  = $this->token($this->claims());

        $this->verifier(['cache' => $shared])->verify($token);           // request 1
        $this->verifier(['cache' => $shared])->verify($token);           // request 2: cached
        $this->assertCount(1, $this->introspections);

        $webhook = $this->verifier(['cache' => $shared]);                // webhook request
        $this->assertSame(1, $webhook->handleEvent(['type' => 'session.revoked', 'data' => ['sid' => 'sid_1']]));
        $this->assertSame(0, $webhook->handleEvent(['type' => 'session.revoked', 'data' => ['sid' => 'sid_1']]));

        $this->verifier(['cache' => $shared])->verify($token);           // request 3: asks again
        $this->assertCount(2, $this->introspections);

        $this->verifier(['cache' => $shared])->clear();
        $this->verifier(['cache' => $shared])->verify($token);
        $this->assertCount(3, $this->introspections);
    }

    public function testAnswersNeverOutliveTheTokenOrTheTtl(): void
    {
        $shared   = new MemoryStorage();
        $verifier = $this->verifier(['cache' => $shared, 'cacheTtl' => 1]);
        $token    = $this->token($this->claims());
        $verifier->verify($token);
        sleep(2);
        $verifier->verify($token);
        $this->assertCount(2, $this->introspections);
    }

    public function testTheLruKeepsAtMostCacheSizeAnswers(): void
    {
        $verifier = $this->verifier(['cacheSize' => 2]);
        $tokens   = [];
        foreach (['a', 'b', 'c'] as $jti) {
            $tokens[$jti] = $this->token($this->claims(['jti' => $jti]));
            $verifier->verify($tokens[$jti]);
        }
        $verifier->verify($tokens['c']);  // cached
        $verifier->verify($tokens['a']);  // evicted (least recently used) → introspected again
        $this->assertCount(4, $this->introspections);
    }

    public function testIntrospectionFailuresAreNotCached(): void
    {
        $fail          = true;
        $this->answers = function () use (&$fail) {
            return $fail ? ['error' => 'invalid_client'] : ['active' => true];
        };
        $this->http->on('POST', self::ISSUER . '/oauth/introspect', function ($url, $headers, $body) use (&$fail) {
            parse_str((string) $body, $form);
            $this->introspections[] = $form['token'];
            return $fail ? new Response(401, [], '{"error":"invalid_client"}') : new Response(200, [], '{"active":true}');
        });
        $verifier = $this->verifier();
        $token    = $this->token($this->claims());
        try {
            $verifier->verify($token);
            $this->fail('expected invalid_client');
        } catch (NineException $e) {
            $this->assertSame('invalid_client', $e->getError());
        }
        $fail = false;
        $this->assertSame('usr_1', $verifier->verify($token)['sub']);
    }

    public function testFactoryReadsTheEnvironment(): void
    {
        putenv('NINE_ISSUER=' . self::ISSUER);
        putenv('NINE_CLIENT_ID=api');
        putenv('NINE_CLIENT_SECRET=secret');
        try {
            $verifier = Nine::createTokenVerifier(['http' => $this->http]);
            $this->assertSame('hybrid', $verifier->mode());
            $this->assertSame('usr_1', $verifier->verify($this->token($this->claims()))['sub']);
        } finally {
            putenv('NINE_ISSUER');
            putenv('NINE_CLIENT_ID');
            putenv('NINE_CLIENT_SECRET');
        }
    }
}
