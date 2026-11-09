<?php

namespace Nine\Tests;

use Nine\Discovery;
use Nine\Exceptions\InsufficientScopeException;
use Nine\Exceptions\InvalidTokenException;
use Nine\Jwt\Jwt;
use Nine\Nine;
use Nine\Storage\MemoryStorage;
use Nine\Tests\Support\TestIssuer;
use Nine\TokenVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TokenVerifierTest extends TestCase
{
    /** @var TestIssuer */
    private $issuer;

    protected function setUp(): void
    {
        Discovery::forget();
        TokenVerifier::forgetKeys();
        $this->issuer = new TestIssuer();
    }

    private function verifier(): TokenVerifier
    {
        return new TokenVerifier(TestIssuer::ISSUER . '/', $this->issuer->http);
    }

    public function testVerifiesAValidToken(): void
    {
        $claims = $this->verifier()->verify($this->issuer->token(), ['audience' => 'https://api.acme.test', 'scope' => 'orders:read']);
        $this->assertSame('usr_123', $claims['sub']);
        $this->assertSame('app_1', $claims['client_id']);
    }

    public function testAcceptsABearerPrefix(): void
    {
        $this->assertSame('usr_123', $this->verifier()->verify('Bearer ' . $this->issuer->token())['sub']);
    }

    public function testCachesKeys(): void
    {
        $verifier = $this->verifier();
        $verifier->verify($this->issuer->token());
        $verifier->verify($this->issuer->token());
        $this->assertCount(1, $this->issuer->http->callsTo(TestIssuer::ISSUER . '/.well-known/jwks.json'));
    }

    /**
     * @return array<string, array{0: callable}>
     */
    public static function invalidTokens(): array
    {
        return [
            'expired'         => [function (TestIssuer $i) { return $i->token(['exp' => time() - 120]); }],
            'not yet valid'   => [function (TestIssuer $i) { return $i->token(['nbf' => time() + 120]); }],
            'wrong issuer'    => [function (TestIssuer $i) { return $i->token(['iss' => 'https://evil.test']); }],
            'alg none'        => [function (TestIssuer $i) { $t = explode('.', $i->token([], ['alg' => 'none'])); return $t[0] . '.' . $t[1] . '.'; }],
            'HS256'           => [function (TestIssuer $i) { return $i->token([], ['alg' => 'HS256']); }],
            'foreign key'     => [function (TestIssuer $i) { return $i->token([], [], TestIssuer::generateKey()); }],
            'unknown kid'     => [function (TestIssuer $i) { return $i->token([], ['kid' => 'nope']); }],
            'malformed'       => [function () { return 'not.a.jwt'; }],
            'tampered claims' => [function (TestIssuer $i) {
                $parts    = explode('.', $i->token());
                $payload  = Jwt::claims($i->token());
                $payload['sub'] = 'usr_admin';
                $parts[1] = Jwt::base64UrlEncode(json_encode($payload));
                return implode('.', $parts);
            }],
        ];
    }

    #[DataProvider('invalidTokens')]
    public function testRejectsInvalidTokens(callable $make): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($make($this->issuer));
    }

    public function testRejectsMissingTokens(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify(null);
    }

    public function testAudienceMismatch(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($this->issuer->token(), ['audience' => 'https://other.api']);
    }

    public function testAudienceArrays(): void
    {
        $token = $this->issuer->token(['aud' => ['https://a.test', 'https://api.acme.test']]);
        $this->assertSame('usr_123', $this->verifier()->verify($token, ['audience' => ['https://x.test', 'https://api.acme.test']])['sub']);
    }

    public function testMissingScopeIs403(): void
    {
        try {
            $this->verifier()->verify($this->issuer->token(), ['scope' => 'orders:read orders:write']);
            $this->fail('expected InsufficientScopeException');
        } catch (InsufficientScopeException $e) {
            $this->assertSame(403, $e->getStatus());
            $this->assertStringContainsString('orders:write', $e->getMessage());
        }
    }

    public function testRefetchesKeysOnceAfterRotation(): void
    {
        $verifier = $this->verifier();
        $verifier->verify($this->issuer->token());

        $rotated = TestIssuer::generateKey();
        $this->issuer->publish($rotated, 'key-2');
        $claims = $verifier->verify($this->issuer->token([], ['kid' => 'key-2'], $rotated));
        $this->assertSame('usr_123', $claims['sub']);
        $this->assertCount(2, $this->issuer->http->callsTo(TestIssuer::ISSUER . '/.well-known/jwks.json'));
    }

    public function testThrottlesUnknownKids(): void
    {
        $verifier = $this->verifier();
        for ($i = 0; $i < 3; $i++) {
            try {
                $verifier->verify($this->issuer->token([], ['kid' => 'junk']));
            } catch (InvalidTokenException $e) {
            }
        }
        // first lookup + one forced refetch, then throttled
        $this->assertCount(2, $this->issuer->http->callsTo(TestIssuer::ISSUER . '/.well-known/jwks.json'));
    }

    public function testUsesTheSharedCache(): void
    {
        $cache = new MemoryStorage();
        (new TokenVerifier(TestIssuer::ISSUER, $this->issuer->http, $cache))->verify($this->issuer->token());
        Discovery::forget();
        TokenVerifier::forgetKeys();
        (new TokenVerifier(TestIssuer::ISSUER, $this->issuer->http, $cache))->verify($this->issuer->token());
        $this->assertCount(1, $this->issuer->http->callsTo(TestIssuer::ISSUER . '/.well-known/jwks.json'));
        $this->assertCount(1, $this->issuer->http->callsTo(TestIssuer::ISSUER . '/.well-known/openid-configuration'));
    }

    public function testStaticShortcut(): void
    {
        $claims = Nine::verifyAccessToken($this->issuer->token(), ['issuer' => TestIssuer::ISSUER, 'http' => $this->issuer->http, 'scope' => ['orders:read']]);
        $this->assertSame('usr_123', $claims['sub']);
    }
}
