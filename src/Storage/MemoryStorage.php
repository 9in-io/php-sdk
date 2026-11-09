<?php

namespace Nine\Storage;

/** Per-process store (tests, CLI scripts, long-running workers). */
final class MemoryStorage implements AtomicStorageInterface
{
    /** @var array<string, array{0: string, 1: int}> */
    private $items = [];

    public function put(string $key, string $value, int $ttl = 0): void
    {
        $this->items[$key] = [$value, $ttl > 0 ? time() + $ttl : 0];
    }

    public function add(string $key, string $value, int $ttl = 0): bool
    {
        if ($this->get($key) !== null) {
            return false;
        }
        $this->put($key, $value, $ttl);
        return true;
    }

    public function get(string $key): ?string
    {
        if (!isset($this->items[$key])) {
            return null;
        }
        [$value, $expires] = $this->items[$key];
        if ($expires > 0 && $expires <= time()) {
            unset($this->items[$key]);
            return null;
        }
        return $value;
    }

    public function delete(string $key): void
    {
        unset($this->items[$key]);
    }
}
