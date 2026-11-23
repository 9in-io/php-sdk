<?php

namespace Nine\Tests;

use Nine\Env;
use Nine\OAuth2Config;
use PHPUnit\Framework\TestCase;

final class EnvTest extends TestCase
{
    private const NAMES = ['NINE_ISSUER', 'NINE_CLIENT_ID', 'NINE_ADAPTER_SECRET', 'SSOFY_URL', 'SSOFY_API_SECRET'];

    protected function tearDown(): void
    {
        foreach (self::NAMES as $name) {
            putenv($name);
            unset($_ENV[$name], $_SERVER[$name]);
        }
    }

    public function testReadsNineNames(): void
    {
        $this->assertNull(Env::source('ISSUER'));
        $_ENV['NINE_ISSUER'] = 'https://acme.9in.io';
        $this->assertSame('https://acme.9in.io', Env::get('ISSUER'));
        $this->assertSame('https://acme.9in.io', Env::get('NINE_ISSUER'));
        $this->assertSame('NINE_ISSUER', Env::source('ISSUER'));
        $this->assertSame('default', Env::get('SOMETHING_UNSET', 'default'));
    }

    public function testIgnoresTheOldSsofyNames(): void
    {
        putenv('SSOFY_URL=https://old.example.test');
        putenv('SSOFY_API_SECRET=old');
        $this->assertNull(Env::get('ISSUER'));
        $this->assertNull(Env::get('ADAPTER_SECRET'));
        $this->assertNull(Env::source('ISSUER'));
    }

    public function testConfigFromEnv(): void
    {
        putenv('NINE_ISSUER=https://login.acme.test');
        putenv('NINE_CLIENT_ID=app_1');
        $config = OAuth2Config::fromEnv(['redirect_uri' => 'https://app.acme.test/cb']);
        $this->assertSame('https://login.acme.test', $config->issuer);
        $this->assertSame('app_1', $config->clientId);
        $this->assertNull($config->clientSecret);
        $this->assertSame('https://app.acme.test/cb', $config->redirectUri);
    }
}
