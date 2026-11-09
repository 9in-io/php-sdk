<?php

namespace Nine\TokenCache;

/** @internal In-process LRU (long-running workers, tests). */
final class MemoryAnswerCache implements AnswerCacheInterface
{
    /** @var array<string, array{claims: array<string, mixed>|null, until: int}> least recently used first */
    private $entries = [];

    /** @var int */
    private $size;

    public function __construct(int $size = 10000)
    {
        $this->size = max(1, $size);
    }

    public function get(string $key): ?array
    {
        if (!isset($this->entries[$key])) {
            return null;
        }
        $entry = $this->entries[$key];
        unset($this->entries[$key]);
        $this->entries[$key] = $entry; // most recently used
        return $entry;
    }

    public function put(string $key, ?array $claims, int $until): void
    {
        unset($this->entries[$key]);
        $this->entries[$key] = ['claims' => $claims, 'until' => $until];
        while (count($this->entries) > $this->size) {
            unset($this->entries[array_key_first($this->entries)]);
        }
    }

    public function evict(string $field, string $value): int
    {
        $evicted = 0;
        foreach ($this->entries as $key => $entry) {
            if ($entry['claims'] !== null && (string) ($entry['claims'][$field] ?? '') === $value) {
                unset($this->entries[$key]);
                $evicted++;
            }
        }
        return $evicted;
    }

    public function clear(): void
    {
        $this->entries = [];
    }

    public function count(): int
    {
        return count($this->entries);
    }
}
