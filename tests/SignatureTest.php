<?php

namespace Nine\Tests;

use Nine\Exceptions\SignatureException;
use Nine\Signature;
use PHPUnit\Framework\TestCase;

final class SignatureTest extends TestCase
{
    private const SECRET = 'adapter_secret_test';
    private const BODY   = '{"identifier":{"type":"email","value":"jane@acme.com"},"password":"hunter2"}';

    public function testMatchesTheReferenceVector(): void
    {
        // Computed with the 9in server's scheme: HMAC-SHA256("t.METHOD.path.body").
        $this->assertSame(
            't=1762682400,v1=f8c341feb9ffa2698aa90a3e762f7108a324e503aa260bbc305e8ba3be9ca49c',
            Signature::sign(self::SECRET, 'post', '/nine/authenticate', self::BODY, 1762682400)
        );
        $this->assertSame(
            't=1762682400,v1=1b9fb41e87bb256836ea5d5d6600270b77578ffd166d84a2cf35ab9841b3585a',
            Signature::sign(self::SECRET, 'POST', '/nine/authenticate#req_123', '{"user":{"id":"42"}}', 1762682400)
        );
    }

    public function testRoundTrip(): void
    {
        $header = Signature::sign(self::SECRET, 'POST', '/nine/user', '{"id":"1"}');
        $this->assertTrue(Signature::verify(self::SECRET, $header, 'POST', '/nine/user', '{"id":"1"}'));
    }

    public function testRejectsTamperedBodyPathAndMethod(): void
    {
        $header = Signature::sign(self::SECRET, 'POST', '/nine/user', '{"id":"1"}');
        $this->assertSame('mismatch', Signature::check(self::SECRET, $header, 'POST', '/nine/user', '{"id":"2"}')['reason']);
        $this->assertSame('mismatch', Signature::check(self::SECRET, $header, 'POST', '/nine/authenticate', '{"id":"1"}')['reason']);
        $this->assertSame('mismatch', Signature::check(self::SECRET, $header, 'GET', '/nine/user', '{"id":"1"}')['reason']);
        $this->assertSame('mismatch', Signature::check('other', $header, 'POST', '/nine/user', '{"id":"1"}')['reason']);
    }

    public function testRejectsReplaysOutsideTheTolerance(): void
    {
        $old = Signature::sign(self::SECRET, 'POST', '/p', 'b', time() - 301);
        $this->assertSame('expired', Signature::check(self::SECRET, $old, 'POST', '/p', 'b')['reason']);
        $this->assertTrue(Signature::verify(self::SECRET, $old, 'POST', '/p', 'b', 600));
        $future = Signature::sign(self::SECRET, 'POST', '/p', 'b', time() + 301);
        $this->assertFalse(Signature::verify(self::SECRET, $future, 'POST', '/p', 'b'));
    }

    public function testMissingAndMalformedHeaders(): void
    {
        $this->assertSame('missing', Signature::check(self::SECRET, null, 'POST', '/p', 'b')['reason']);
        $this->assertSame('missing', Signature::check(self::SECRET, '', 'POST', '/p', 'b')['reason']);
        foreach (['garbage', 't=abc,v1=' . str_repeat('a', 64), 't=1', 'v1=' . str_repeat('a', 64), 't=1,v1=ABC', '=x'] as $bad) {
            $this->assertSame('malformed', Signature::check(self::SECRET, $bad, 'POST', '/p', 'b')['reason'], $bad);
        }
    }

    public function testSecretRotationAndMultipleSignatures(): void
    {
        $header = Signature::sign('new-secret', 'POST', '/p', 'b');
        $this->assertTrue(Signature::verify(['old-secret', 'new-secret'], $header, 'POST', '/p', 'b'));

        $t        = time();
        $old      = Signature::sign('old-secret', 'POST', '/p', 'b', $t);
        $combined = $old . ',' . explode(',', Signature::sign('new-secret', 'POST', '/p', 'b', $t))[1];
        $this->assertTrue(Signature::verify('new-secret', $combined, 'POST', '/p', 'b'));
    }

    public function testAssertThrows(): void
    {
        $this->expectException(SignatureException::class);
        Signature::assert(self::SECRET, 't=1,v1=' . str_repeat('0', 64), 'POST', '/p', 'b');
    }
}
