<?php

namespace Nine\Storage;

/**
 * Key/value store with expiry, used for login state (PKCE verifier, nonce) and for
 * caching discovery documents and signing keys. Bridge it to your framework's cache.
 */
interface StorageInterface
{
    /**
     * @param int $ttl time-to-live in seconds; 0 keeps the value until deleted
     */
    public function put(string $key, string $value, int $ttl = 0): void;

    public function get(string $key): ?string;

    public function delete(string $key): void;
}
