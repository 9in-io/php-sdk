<?php

namespace Nine\Tests;

use Nine\Discovery;
use Nine\Exceptions\InvalidTokenException;
use Nine\Http\Response;
use Nine\Tests\Support\FakeHttpClient;
use Nine\Tests\Support\Signers;
use Nine\TokenVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Every algorithm 9in signs access tokens with: vectors signed by WebCrypto (as used by
 * @9in-io/sdk and the 9in server) and tokens signed here with PHP.
 */
final class AlgorithmsTest extends TestCase
{
    /** @var array<string, mixed> */
    private static $vectors;

    public static function setUpBeforeClass(): void
    {
        self::$vectors = json_decode((string) file_get_contents(__DIR__ . '/fixtures/jws-vectors.json'), true);
    }

    protected function setUp(): void
    {
        Discovery::forget();
        TokenVerifier::forgetKeys();
    }

    /**
     * @param array<int, array<string, mixed>> $keys
     */
    private function verifier(string $issuer, array $keys): TokenVerifier
    {
        $http = (new FakeHttpClient())
            ->json('GET', $issuer . '/.well-known/openid-configuration', ['issuer' => $issuer, 'token_endpoint' => $issuer . '/oauth/token', 'jwks_uri' => $issuer . '/.well-known/jwks.json'])
            ->on('GET', $issuer . '/.well-known/jwks.json', function () use (&$keys) {
                return new Response(200, [], json_encode(['keys' => $keys]));
            });
        return new TokenVerifier($issuer, $http);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function algorithms(): array
    {
        $out = [];
        foreach (['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'EdDSA', 'HS256', 'HS384', 'HS512'] as $alg) {
            $out[$alg] = [$alg];
        }
        return $out;
    }

    #[DataProvider('algorithms')]
    public function testVerifiesWebCryptoVectors(string $alg): void
    {
        $v      = self::$vectors;
        $claims = $this->verifier($v['issuer'], $v['jwks']['keys'])->verify($v['tokens'][$alg], [
            'audience' => 'https://api.acme.test',
            'scope'    => 'orders:read',
            'secret'   => $v['hmacSecret'],
        ]);
        $this->assertSame('usr_1', $claims['sub']);
        $this->assertSame('jti_1', $claims['jti']);
    }

    #[DataProvider('algorithms')]
    public function testVerifiesPhpSignedTokens(string $alg): void
    {
        $issuer = 'https://php-' . strtolower($alg) . '.9in.test';
        $claims = ['iss' => $issuer, 'sub' => 'usr_2', 'aud' => 'https://api.acme.test', 'scope' => 'orders:read', 'iat' => time(), 'exp' => time() + 300];
        if ($alg[0] === 'H') {
            $token  = Signers::hmac($alg, 'php-secret-of-sufficient-length-123', $claims);
            $result = $this->verifier($issuer, [])->verify($token, ['secret' => 'php-secret-of-sufficient-length-123']);
        } else {
            [$sign, $jwk] = Signers::key($alg);
            $token  = Signers::jwt($sign, ['alg' => $alg, 'typ' => 'at+jwt', 'kid' => 'k1'], $claims);
            $result = $this->verifier($issuer, [$jwk])->verify($token);
        }
        $this->assertSame('usr_2', $result['sub']);
    }

    public function testTamperedSignaturesFailForEveryAlgorithm(): void
    {
        $v        = self::$vectors;
        $verifier = $this->verifier($v['issuer'], $v['jwks']['keys']);
        foreach ($v['tokens'] as $alg => $token) {
            $parts    = explode('.', $token);
            $payload  = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
            $payload['sub'] = 'usr_admin';
            $parts[1] = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '=');
            try {
                $verifier->verify(implode('.', $parts), ['secret' => $v['hmacSecret']]);
                $this->fail("{$alg}: tampered token accepted");
            } catch (InvalidTokenException $e) {
                $this->assertStringContainsString('signature', $e->getMessage(), $alg);
            }
        }
    }

    public function testRsaPssRequiresTheJwsSaltLength(): void
    {
        $v = self::$vectors;
        $this->expectExceptionMessage('bad signature');
        $this->verifier($v['issuer'], $v['jwks']['keys'])->verify($v['invalid']['PS256 salt length 0']);
    }

    public function testRejectsIdTokens(): void
    {
        $v = self::$vectors;
        $this->expectExceptionMessage('not an access token');
        $this->verifier($v['issuer'], $v['jwks']['keys'])->verify($v['invalid']['ES256 ID token (typ JWT)']);
    }

    public function testAcceptsTheMediaTypeFormOfTyp(): void
    {
        [$sign, $jwk] = Signers::key('ES256');
        $issuer = 'https://typ.9in.test';
        $token  = Signers::jwt($sign, ['alg' => 'ES256', 'typ' => 'Application/AT+JWT', 'kid' => 'k1'], ['iss' => $issuer, 'sub' => 'u', 'exp' => time() + 60]);
        $this->assertSame('u', $this->verifier($issuer, [$jwk])->verify($token)['sub']);
    }

    public function testTheKeyDecidesTheAlgorithm(): void
    {
        $v    = self::$vectors;
        $keys = $v['jwks']['keys'];
        foreach ($keys as &$key) {
            if ($key['kid'] === 'k-PS256') {
                $key['alg'] = 'RS256'; // the JWKS says RS256, the token says PS256
            }
        }
        unset($key);
        try {
            $this->verifier($v['issuer'], $keys)->verify($v['tokens']['PS256']);
            $this->fail('accepted a token whose alg differs from its key');
        } catch (InvalidTokenException $e) {
            $this->assertStringContainsString('does not match the key', $e->getMessage());
        }

        // A key without `alg` still has to fit: an ES256 header pointing at an RSA key.
        [$sign]       = Signers::key('ES256');
        [, $rsaJwk]   = Signers::key('RS256', 'rsa');
        unset($rsaJwk['alg']);
        $issuer = 'https://mix.9in.test';
        $token  = Signers::jwt($sign, ['alg' => 'ES256', 'typ' => 'at+jwt', 'kid' => 'rsa'], ['iss' => $issuer, 'sub' => 'u', 'exp' => time() + 60]);
        $this->expectExceptionMessage('does not match the key');
        $this->verifier($issuer, [$rsaJwk])->verify($token);
    }

    public function testHmacTokensNeedTheRightSecret(): void
    {
        $v        = self::$vectors;
        $verifier = $this->verifier($v['issuer'], $v['jwks']['keys']);
        try {
            $verifier->verify($v['tokens']['HS256']);
            $this->fail('accepted an HMAC token without a secret');
        } catch (InvalidTokenException $e) {
            $this->assertStringContainsString('secret', $e->getMessage());
        }
        try {
            $verifier->verify($v['tokens']['HS256'], ['secret' => $v['hmacSecret'] . 'x']);
            $this->fail('accepted an HMAC token with the wrong secret');
        } catch (InvalidTokenException $e) {
            $this->assertStringContainsString('bad signature', $e->getMessage());
        }
    }

    public function testIdTokensVerifyWithAnyAsymmetricKeyButNotHmac(): void
    {
        foreach (['PS256', 'ES384', 'EdDSA'] as $alg) {
            Discovery::forget();
            TokenVerifier::forgetKeys();
            [$sign, $jwk] = Signers::key($alg);
            $issuer = 'https://id-' . strtolower($alg) . '.9in.test';
            $token  = Signers::jwt($sign, ['alg' => $alg, 'typ' => 'JWT', 'kid' => 'k1'], ['iss' => $issuer, 'sub' => 'u', 'aud' => 'app_1', 'nonce' => 'n1', 'exp' => time() + 60]);
            $this->assertSame('u', $this->verifier($issuer, [$jwk])->verifyIdToken($token, 'app_1', 'n1')['sub'], $alg);
        }
        $hs = Signers::hmac('HS256', 'whatever-secret', ['iss' => 'https://id.9in.test', 'aud' => 'app_1', 'exp' => time() + 60]);
        $this->expectExceptionMessage('unsupported algorithm');
        $this->verifier('https://id.9in.test', [])->verifyIdToken($hs, 'app_1');
    }

    public function testRejectsUnknownAlgorithms(): void
    {
        $issuer = 'https://none.9in.test';
        $token  = Signers::jwt(function () {
            return '';
        }, ['alg' => 'none', 'typ' => 'at+jwt'], ['iss' => $issuer, 'exp' => time() + 60]);
        $this->expectExceptionMessage('unsupported algorithm');
        $this->verifier($issuer, [])->verify($token);
    }
}
