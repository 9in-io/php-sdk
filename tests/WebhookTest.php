<?php

namespace Nine\Tests;

use Nine\Exceptions\NineException;
use Nine\Exceptions\SignatureException;
use Nine\Signature;
use Nine\Webhook;
use PHPUnit\Framework\TestCase;

final class WebhookTest extends TestCase
{
    private const SECRET = 'whsec_test';

    private function body(): string
    {
        return json_encode([
            'id'          => 'evt_1',
            'event_type'  => 'user.created',
            'created_at'  => '2026-11-09T10:00:00.000Z',
            'tenant'      => 'tnt_1',
            'environment' => 'production',
            'data'        => ['user' => ['id' => 'usr_1', 'email' => 'jane@acme.com']],
        ]);
    }

    public function testReturnsTheVerifiedEvent(): void
    {
        $body  = $this->body();
        $event = Webhook::verify(self::SECRET, $body, Signature::sign(self::SECRET, 'POST', '/webhooks/9in', $body), '/webhooks/9in');
        $this->assertSame('user.created', $event['event_type']);
        $this->assertSame('2026-11-09T10:00:00.000Z', $event['created_at']);
        $this->assertSame('usr_1', $event['data']['user']['id']);
        $this->assertSame('9in-event-type', Webhook::EVENT_TYPE_HEADER);
    }

    public function testRejectsAnotherPathOrSecret(): void
    {
        $body = $this->body();
        $this->expectException(SignatureException::class);
        Webhook::verify(self::SECRET, $body, Signature::sign(self::SECRET, 'POST', '/other', $body), '/webhooks/9in');
    }

    public function testRejectsOldDeliveries(): void
    {
        $body = $this->body();
        try {
            Webhook::verify(self::SECRET, $body, Signature::sign(self::SECRET, 'POST', '/w', $body, time() - 3600), '/w');
            $this->fail('expected expired');
        } catch (SignatureException $e) {
            $this->assertSame('expired', $e->getReason());
            $this->assertSame(401, $e->getStatus());
        }
    }

    public function testRejectsNonEvents(): void
    {
        $this->expectException(NineException::class);
        Webhook::verify(self::SECRET, '[]', Signature::sign(self::SECRET, 'POST', '/w', '[]'), '/w');
    }
}
