<?php

namespace Nine\Tests;

use Nine\Exceptions\NineException;
use Nine\Issuer;
use Nine\ManagementClient;
use Nine\OAuth2Config;
use Nine\TokenVerifier;
use PHPUnit\Framework\TestCase;

final class IssuerTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('NINE_ALLOW_INSECURE_ISSUER');
    }

    public function testRequiresHttpsExceptForLocalhost(): void
    {
        $this->assertSame('https://acme.9in.io', Issuer::normalize('https://acme.9in.io/'));
        foreach (['http://localhost:8787', 'http://acme.localhost:8787', 'http://127.0.0.1:8897', 'http://[::1]:8897'] as $local) {
            $this->assertSame($local, Issuer::normalize($local));
        }
        foreach (['http://acme.9in.io', 'http://login.acme.com', 'http://localhost.evil.com'] as $insecure) {
            try {
                Issuer::normalize($insecure);
                $this->fail("accepted {$insecure}");
            } catch (NineException $e) {
                $this->assertSame('insecure_issuer', $e->getError());
            }
        }
    }

    public function testRejectsMalformedIssuers(): void
    {
        foreach (['acme.9in.io', 'https://acme.9in.io/?x=1', 'https://acme.9in.io/#f', 'https://user:pw@acme.9in.io', 'ftp://acme.9in.io'] as $invalid) {
            try {
                Issuer::normalize($invalid);
                $this->fail("accepted {$invalid}");
            } catch (NineException $e) {
                $this->assertContains($e->getError(), ['invalid_issuer', 'insecure_issuer']);
            }
        }
    }

    public function testOptOuts(): void
    {
        $this->assertSame('http://auth:8897', Issuer::normalize('http://auth:8897', true));
        putenv('NINE_ALLOW_INSECURE_ISSUER=true');
        $this->assertSame('http://auth:8897', Issuer::normalize('http://auth:8897'));
    }

    public function testEnforcedByEveryEntryPoint(): void
    {
        $constructors = [
            function () { new OAuth2Config(['issuer' => 'http://acme.9in.io', 'client_id' => 'a']); },
            function () { new TokenVerifier('http://acme.9in.io'); },
            function () { new ManagementClient('http://acme.9in.io', 'a', 's'); },
        ];
        foreach ($constructors as $make) {
            try {
                $make();
                $this->fail('accepted an http issuer');
            } catch (NineException $e) {
                $this->assertSame('insecure_issuer', $e->getError());
            }
        }
        $config = new OAuth2Config(['issuer' => 'http://auth.internal', 'client_id' => 'a', 'allow_insecure_issuer' => true]);
        $this->assertSame('http://auth.internal', $config->issuer);
        $this->assertSame('http://auth.internal', (new \Nine\OAuth2Client($config))->verifier()->issuer());
    }
}
