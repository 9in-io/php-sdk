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
        $this->issuer->http->json('GET', TestIssuer::ISSUER . '/api/v1/users', ['users' => [], 'next_cursor' => null, 'total' => 0]);
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
                return new Response(201, [], json_encode(['url' => 'https://acme.9in.test/login-link/abc', 'expires_at' => '2026-11-10T09:40:00.000Z', 'echo' => json_decode($body, true)]));
            }
            return new Response(201, [], json_encode(['user' => ['id' => 'usr_1'] + json_decode($body, true)]));
        });
        $client = $this->client();
        $user   = $client->createUser(['email' => 'jane@acme.com', 'email_verified' => true]);
        $this->assertSame('usr_1', $user['id']);
        $this->assertTrue($user['email_verified']);

        $link = $client->createLoginLink('usr_1', ['returnTo' => 'https://app.acme.test/cb', 'ttlSeconds' => 600]);
        $this->assertSame('https://acme.9in.test/login-link/abc', $link['url']);
        $this->assertSame('2026-11-10T09:40:00.000Z', $link['expires_at']);
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
        $this->assertNull($this->client()->findUser('phone_number', '+447700900000'));
        $this->assertStringEndsWith('/api/v1/users/lookup?phone_number=%2B447700900000', $this->issuer->http->calls[count($this->issuer->http->calls) - 1]['url']);
        $this->expectException(\InvalidArgumentException::class);
        $this->client()->findUser('phone', '+447700900000');
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

    public function testImportsInBulkWithConflictModeAndSource(): void
    {
        $this->issuer->http->on('POST', TestIssuer::ISSUER . '/api/v1/users/import', function ($url, $headers, $body) {
            return new Response(200, [], json_encode(['results' => [['index' => 0, 'ok' => true, 'status' => 'created', 'id' => 'auth0|42']], 'echo' => json_decode($body, true)]));
        });
        $client  = $this->client();
        $results = $client->importUsers([['id' => 'auth0|42', 'email' => 'jane@acme.com', 'password_hash' => '$2b$10$x', 'created_at' => '2020-01-01T00:00:00Z']], ['onConflict' => 'update', 'source' => 'auth0']);
        $this->assertSame('created', $results[0]['status']);
        $sent = json_decode((string) $this->issuer->http->callsTo(TestIssuer::ISSUER . '/api/v1/users/import')[0]['body'], true);
        $this->assertSame(['users', 'on_conflict', 'source'], array_keys($sent));
        $this->assertSame(['update', 'auth0'], [$sent['on_conflict'], $sent['source']]);

        $client->importUsers([['email' => 'b@acme.com']]);
        $plain = json_decode((string) $this->issuer->http->callsTo(TestIssuer::ISSUER . '/api/v1/users/import')[1]['body'], true);
        $this->assertSame(['users'], array_keys($plain));
    }

    public function testListsAndEndsSessions(): void
    {
        $this->issuer->http->json('GET', TestIssuer::ISSUER . '/api/v1/users/usr_1/sessions', ['sessions' => [['sid' => 's1', 'user_id' => 'usr_1']]]);
        $this->issuer->http->on('DELETE', TestIssuer::ISSUER . '/api/v1/sessions/', function () {
            return new Response(204, [], '');
        });
        $client = $this->client();
        $this->assertSame('s1', $client->listUserSessions('usr_1')[0]['sid']);
        $client->revokeSession('s/1');
        $this->assertSame(TestIssuer::ISSUER . '/api/v1/sessions/s%2F1', $this->issuer->http->callsTo(TestIssuer::ISSUER . '/api/v1/sessions/')[0]['url']);
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
