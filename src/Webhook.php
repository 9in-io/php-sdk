<?php

namespace Nine;

use Nine\Exceptions\NineException;
use Nine\Exceptions\SignatureException;

/**
 * Verifies webhooks from 9in (same signature scheme as the adapter protocol, over the raw
 * body and the path 9in posted to) and returns the parsed event.
 *
 *   $event = Webhook::verify(getenv('NINE_WEBHOOK_SECRET'), file_get_contents('php://input'),
 *       $_SERVER['HTTP_9IN_SIGNATURE'] ?? null, parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
 *   if ($event['event'] === 'user.created') { … }
 *
 * An event is `{id, event, created_at, tenant, environment, data}` (snake_case, ISO 8601 UTC
 * times); `data['user']` is the user it is about, or null. Its `id` stays the same on every
 * retry and redelivery, so you can ignore duplicates.
 */
final class Webhook
{
    public const EVENTS = [
        'user.created',
        'user.updated',
        'user.deleted',
        'user.login',
        'user.login_failed',
        'user.password_changed',
        'user.mfa_enabled',
        'user.mfa_disabled',
        'user.sessions_revoked',
        'session.revoked',
        'token.revoked',
        'webhook.test',
    ];

    public const EVENT_ID_HEADER    = '9in-event-id';
    /** The event name (also the body's `event`). */
    public const EVENT_HEADER       = '9in-event';
    public const DELIVERY_ID_HEADER = '9in-delivery-id';

    /**
     * @param string|string[] $secret signing secret(s) of the webhook endpoint
     * @param string          $path   the path 9in posted to (as in your endpoint URL, without query string)
     * @return array{id: string, event: string, created_at: string, tenant: string, environment: string, data: array<string, mixed>}
     * @throws SignatureException
     * @throws NineException      invalid_payload when the body is not a JSON event
     */
    public static function verify($secret, string $body, ?string $signatureHeader, string $path, int $toleranceSeconds = Signature::DEFAULT_TOLERANCE, string $method = 'POST'): array
    {
        if (strtoupper($method) !== 'POST') {
            throw new SignatureException('mismatch', 'webhooks are POST requests');
        }
        Signature::assert($secret, $signatureHeader, 'POST', $path, $body, $toleranceSeconds);
        $event = json_decode($body, true);
        if (!is_array($event) || !isset($event['id'], $event['event'])) {
            throw new NineException('invalid_payload', 'webhook body is not a JSON event', 400);
        }
        return $event;
    }
}
