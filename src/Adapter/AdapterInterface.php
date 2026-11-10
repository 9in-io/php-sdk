<?php

namespace Nine\Adapter;

/**
 * Your user database, as seen by 9in (adapter protocol v2).
 *
 * Identifiers are arrays `['type' => 'email'|'username'|'phone', 'value' => '…']`.
 */
interface AdapterInterface
{
    public const INVALID = 'invalid';
    public const BLOCKED = 'blocked';

    /**
     * Checks a password. Return the user, AdapterInterface::INVALID (unknown user or wrong
     * password — 9in does not tell them apart) or AdapterInterface::BLOCKED.
     *
     * @param array{type: string, value: string} $identifier
     * @return AdapterUser|string
     */
    public function authenticate(array $identifier, string $password);

    /**
     * Looks a user up by `['id' => '…']` or `['identifier' => ['type' => …, 'value' => …]]`.
     *
     * @param array<string, mixed> $query
     */
    public function findUser(array $query): ?AdapterUser;

    /**
     * Notifications: otp.requested (deliver the code yourself), user.created, user.updated,
     * user.password_changed, session.revoked.
     *
     * `otp.requested` data: user_id (your id), channel, to, code, purpose, expires_at (ISO 8601);
     * user.updated / user.password_changed: user_id, fields.
     *
     * @param array{id: string, event: string, created_at: string, data: array<string, mixed>} $event
     */
    public function onEvent(array $event): void;
}
