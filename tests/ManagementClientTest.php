<?php

namespace Nine\Tests;

use Nine\Discovery;
use Nine\Exceptions\NineException;
use Nine\Http\Response;
use Nine\ManagementClient;
use Nine\Tests\Support\TestIssuer;
use PHPUnit\Framework\TestCase;

final class ManagementClientTest extends TestCase
{
    /** @var TestIssuer */
    private $issuer;

    protected function setUp(): void
    {
        Discovery::forget();
        $this->issuer = new TestIssuer();
        $this->issuer->http->json('POST', TestIssuer::ISSUER . '/oauth/token', ['access_token' => 'mgmt_token', 'expires_in' => 3600, 'token_type' => 'Bearer']);
    }

    private function client(): ManagementClient
    {
        return new ManagementClient(TestIssuer::ISSUER, 'app_m2m', 'secret', $this->issuer->http);
    }

    public function testUsesOneClientCredentialsTokenForSeveralCalls(): void
    {
        $this->issuer->http->json('GET', TestIssuer::ISSUER . '/api/v1/users', ['users' => [], 'nextCursor' => null, 'total' => 0]);
        $client = $this->client();
        $client->listUsers(['query' => 'jane', 'limit' => 10]);
        $client->listUsers();

        $tokenCalls = $this->issuer->http->callsTo(TestIssuer::ISSUER . '/oauth/token');
        $this->assertCount(1, $tokenCalls);
        parse_str((string) $tokenCalls[0]['body'], $form);
        $this->assertSame('client_credentials', $form['grant_type']);
        // Each call asks for the scope it needs, so an app granted only some scopes works.
        $this->assertSame('management:users:read', $form['scope']);
        $this->assertSame('Basic ' . base64_encode('app_m2m:secret'), $tokenCalls[0]['headers']['Authorization']);

        $calls = $this->issuer->http->callsTo(TestIssuer::ISSUER . '/api/v1/users');
        $this->assertSame(TestIssuer::ISSUER . '/api/v1/users?q=jane&limit=10', $calls[0]['url']);
        $this->assertSame('Bearer mgmt_token', $calls[0]['headers']['Authorization']);
    }

    public function testCreatesUsersAndLoginLinks(): void
    {
        $this->issuer->http->on('POST', TestIssuer::ISSUER . '/api/v1/users', function ($url, $headers, $body) {
            if (substr($url, -11) === '/login-link') {
                return new Response(201, [], json_encode(['url' => 'https://acme.9in.test/login-link/abc', 'expires_at' => 1, 'echo' => json_decode($body, true)]));
            }
            return new Response(201, [], json_encode(['user' => ['id' => 'usr_1'] + json_decode($body, true)]));
        });
        $client = $this->client();
        $user   = $client->createUser(['email' => 'jane@acme.com', 'emailVerified' => true]);
        $this->assertSame('usr_1', $user['id']);

        $link = $client->createLoginLink('usr_1', ['returnTo' => 'https://app.acme.test/cb', 'ttlSeconds' => 600]);
        $this->assertSame('https://acme.9in.test/login-link/abc', $link['url']);
        $this->assertSame(['return_to' => 'https://app.acme.test/cb', 'ttl_seconds' => 600], $link['echo']);

        $empty = $client->createLoginLink('usr_1');
        $this->assertSame([], $empty['echo']);
        $last = $this->issuer->http->calls[count($this->issuer->http->calls) - 1];
        $this->assertSame('{}', $last['body']);
    }

    public function testLookupReturnsNullOn404(): void
    {
        $this->issuer->http->json('GET', TestIssuer::ISSUER . '/api/v1/users/lookup', ['error' => 'not_found'], 404);
        $this->assertNull($this->client()->findUserByEmail('nobody@acme.com'));
        $this->assertStringEndsWith('/api/v1/users/lookup?email=nobody%40acme.com', $this->issuer->http->calls[count($this->issuer->http->calls) - 1]['url']);
    }

    public function testDeleteAndSessions(): void
    {
        $this->issuer->http->on('DELETE', TestIssuer::ISSUER . '/api/v1/users/usr%2F1', function ($url) {
            return substr($url, -9) === '/sessions'
                ? new Response(200, [], '{"revoked":3}')
                : new Response(204, [], '');
        });
        $client = $this->client();
        $client->deleteUser('usr/1');
        $this->assertSame(3, $client->revokeUserSessions('usr/1'));
    }

    public function testErrorsCarryCodeAndStatus(): void
    {
        $this->issuer->http->json('PATCH', TestIssuer::ISSUER . '/api/v1/users/usr_1', ['error' => 'identifier_taken'], 409);
        try {
            $this->client()->updateUser('usr_1', ['email' => 'taken@acme.com']);
            $this->fail('expected identifier_taken');
        } catch (NineException $e) {
            $this->assertSame('identifier_taken', $e->getError());
            $this->assertSame(409, $e->getStatus());
        }
    }
}
