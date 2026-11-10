<?php

namespace Nine\Tests;

use Nine\Adapter\AdapterHandler;
use Nine\Adapter\AdapterInterface;
use Nine\Adapter\AdapterResponse;
use Nine\Adapter\AdapterUser;
use Nine\Signature;
use PHPUnit\Framework\TestCase;

final class AdapterHandlerTest extends TestCase
{
    private const SECRET = 'adapter_secret';

    /** @var AdapterInterface */
    private $adapter;

    protected function setUp(): void
    {
        $this->adapter = new class () implements AdapterInterface {
            /** @var array<int, array<string, mixed>> */
            public $events = [];

            public function authenticate(array $identifier, string $password)
            {
                if ($identifier['value'] === 'blocked@acme.com') {
                    return self::BLOCKED;
                }
                if ($identifier === ['type' => 'email', 'value' => 'jane@acme.com'] && $password === 'hunter2') {
                    return new AdapterUser(['id' => 42, 'email' => 'jane@acme.com', 'email_verified' => 1, 'metadata' => [], 'unknown' => 'dropped']);
                }
                return self::INVALID;
            }

            public function findUser(array $query): ?AdapterUser
            {
                if (($query['id'] ?? null) === '42' || ($query['identifier']['value'] ?? null) === 'jane') {
                    return new AdapterUser(['id' => '42', 'username' => 'jane']);
                }
                return null;
            }

            public function onEvent(array $event): void
            {
                $this->events[] = $event;
            }
        };
    }

    /**
     * @param array<string, mixed>|string $body
     */
    private function call(string $path, $body, ?string $secret = self::SECRET, string $requestId = 'req_1', string $method = 'POST'): AdapterResponse
    {
        $raw     = is_string($body) ? $body : json_encode($body);
        $headers = ['9in-Request-Id' => $requestId, 'Content-Type' => 'application/json'];
        if ($secret !== null) {
            $headers['9in-Signature'] = Signature::sign($secret, 'POST', $path, $raw);
        }
        return (new AdapterHandler([self::SECRET, 'previous'], $this->adapter))->handle($method, $path, $headers, $raw);
    }

    private function assertSignedFor(AdapterResponse $response, string $path, string $requestId = 'req_1'): void
    {
        $this->assertTrue(
            Signature::verify(self::SECRET, $response->headers['9in-signature'] ?? null, 'POST', $path . '#' . $requestId, $response->body),
            'response must be signed over path#request-id'
        );
    }

    public function testAuthenticatesAndSignsTheResponse(): void
    {
        $response = $this->call('/nine/authenticate', ['identifier' => ['type' => 'email', 'value' => 'jane@acme.com'], 'password' => 'hunter2']);
        $this->assertSame(200, $response->status);
        $this->assertSame('{"user":{"id":"42","email":"jane@acme.com","email_verified":true,"metadata":{}}}', $response->body);
        $this->assertSignedFor($response, '/nine/authenticate');
        $this->assertFalse(Signature::verify(self::SECRET, $response->headers['9in-signature'], 'POST', '/nine/authenticate#req_2', $response->body));
    }

    public function testWrongPasswordAndBlockedUsers(): void
    {
        $wrong = $this->call('/nine/authenticate', ['identifier' => ['type' => 'email', 'value' => 'jane@acme.com'], 'password' => 'nope']);
        $this->assertSame(401, $wrong->status);
        $this->assertSame('{"error":"invalid_credentials"}', $wrong->body);
        $this->assertSignedFor($wrong, '/nine/authenticate');

        $blocked = $this->call('/nine/authenticate', ['identifier' => ['type' => 'email', 'value' => 'blocked@acme.com'], 'password' => 'x']);
        $this->assertSame(403, $blocked->status);
        $this->assertSame('{"error":"blocked"}', $blocked->body);
    }

    public function testFindsUsersByIdAndIdentifier(): void
    {
        $this->assertSame(200, $this->call('/nine/user', ['id' => '42'])->status);
        $byIdentifier = $this->call('/nine/user', ['identifier' => ['type' => 'username', 'value' => 'jane']]);
        $this->assertSame('{"user":{"id":"42","username":"jane"}}', $byIdentifier->body);
        $missing = $this->call('/nine/user', ['id' => '7']);
        $this->assertSame(404, $missing->status);
        $this->assertSame('{"error":"not_found"}', $missing->body);
        $this->assertSignedFor($missing, '/nine/user');
    }

    public function testEventsAre204AndSigned(): void
    {
        $event    = ['id' => 'evt_1', 'event_type' => 'otp.requested', 'created_at' => '2026-11-09T10:00:00.000Z', 'data' => ['user_id' => '42', 'code' => '123456', 'channel' => 'email', 'to' => 'jane@acme.com', 'expires_at' => '2026-11-09T10:10:00.000Z']];
        $response = $this->call('/adapter/event', $event);
        $this->assertSame(204, $response->status);
        $this->assertSame('', $response->body);
        $this->assertSignedFor($response, '/adapter/event');
        $this->assertSame([$event], $this->adapter->events);
    }

    public function testRejectsUnsignedOrForeignRequests(): void
    {
        $this->assertSame(401, $this->call('/nine/user', ['id' => '42'], null)->status);
        $forged = $this->call('/nine/user', ['id' => '42'], 'wrong-secret');
        $this->assertSame(401, $forged->status);
        $this->assertSame('{"error":"invalid_signature"}', $forged->body);
        $this->assertArrayNotHasKey('9in-signature', $forged->headers);
    }

    public function testAcceptsThePreviousSecretDuringRotation(): void
    {
        $this->assertSame(200, $this->call('/nine/user', ['id' => '42'], 'previous')->status);
    }

    public function testRejectsReplaysToAnotherEndpoint(): void
    {
        $body     = json_encode(['id' => '42']);
        $header   = Signature::sign(self::SECRET, 'POST', '/nine/user', $body);
        $response = (new AdapterHandler(self::SECRET, $this->adapter))->handle('POST', '/nine/authenticate', ['9in-signature' => $header], $body);
        $this->assertSame(401, $response->status);
    }

    public function testBadInput(): void
    {
        $this->assertSame(405, $this->call('/nine/user', ['id' => '42'], self::SECRET, 'r', 'GET')->status);
        $this->assertSame(400, $this->call('/nine/user', 'not json')->status);
        $this->assertSame(400, $this->call('/nine/authenticate', ['identifier' => ['type' => 'fax', 'value' => '1'], 'password' => 'x'])->status);
        $this->assertSame(400, $this->call('/nine/user', [])->status);
        $this->assertSame(404, $this->call('/nine/users', ['id' => '42'])->status);
    }
}
