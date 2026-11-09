<?php

namespace Nine\Tests;

use Nine\Env;
use Nine\OAuth2Config;
use PHPUnit\Framework\TestCase;

final class EnvTest extends TestCase
{
    private const NAMES = ['NINE_ISSUER', 'SSOFY_URL', 'SSOFY_ISSUER', 'NINE_CLIENT_ID', 'SSOFY_CLIENT_ID', 'NINE_ADAPTER_SECRET', 'SSOFY_API_SECRET', 'NINE_CACHE_TTL', 'SSOFY_CACHE_TTL'];

    protected function tearDown(): void
    {
        foreach (self::NAMES as $name) {
            putenv($name);
            unset($_ENV[$name], $_SERVER[$name]);
        }
    }

    public function testPrefersNineNames(): void
    {
        putenv('SSOFY_URL=https://old.ssofy.test');
        $this->assertSame('https://old.ssofy.test', Env::get('ISSUER'));
        $this->assertSame('SSOFY_URL', Env::source('ISSUER'));

        $_ENV['NINE_ISSUER'] = 'https://acme.9in.io';
        $this->assertSame('https://acme.9in.io', Env::get('NINE_ISSUER'));
        $this->assertSame('NINE_ISSUER', Env::source('ISSUER'));
    }

    public function testFallsBackToSsofyNames(): void
    {
        putenv('SSOFY_API_SECRET=legacy');
        $this->assertSame('legacy', Env::get('ADAPTER_SECRET'));
        putenv('SSOFY_CACHE_TTL=60');
        $this->assertSame('60', Env::get('CACHE_TTL'));
        $this->assertSame('default', Env::get('SOMETHING_UNSET', 'default'));
    }

    public function testConfigFromEnv(): void
    {
        putenv('SSOFY_URL=https://login.acme.test');
        putenv('NINE_CLIENT_ID=app_1');
        $config = OAuth2Config::fromEnv(['redirect_uri' => 'https://app.acme.test/cb']);
        $this->assertSame('https://login.acme.test', $config->issuer);
        $this->assertSame('app_1', $config->clientId);
        $this->assertNull($config->clientSecret);
        $this->assertSame('https://app.acme.test/cb', $config->redirectUri);
    }
}
