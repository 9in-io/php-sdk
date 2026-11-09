<?php

namespace Nine\Storage;

/** Stores nothing (disables caching and de-duplication: add() always succeeds). */
final class NullStorage implements AtomicStorageInterface
{
    public function put(string $key, string $value, int $ttl = 0): void
    {
    }

    public function add(string $key, string $value, int $ttl = 0): bool
    {
        return true;
    }

    public function get(string $key): ?string
    {
        return null;
    }

    public function delete(string $key): void
    {
    }
}
