<?php

namespace Nine\TokenCache;

use Nine\Storage\StorageInterface;

/**
 * @internal Answers in a shared StorageInterface (Laravel cache, APCu, Redis…), so they
 * survive across PHP requests and workers.
 *
 * A key-value store cannot be scanned, so positive answers are also listed under index
 * keys for their jti, sid and sub; handleEvent() reads the index to find what to evict.
 * Index updates are read-modify-write: under heavy concurrency an index can miss an entry,
 * which then expires after `cacheTtl` at the latest instead of being evicted at once.
 */
final class StorageAnswerCache implements AnswerCacheInterface
{
    private const INDEXED   = ['jti', 'sid', 'sub'];
    private const INDEX_MAX = 500;

    /** @var StorageInterface */
    private $store;

    /** @var int */
    private $ttl;

    /** @var string|null */
    private $prefix;

    public function __construct(StorageInterface $store, int $ttlSeconds)
    {
        $this->store = $store;
        $this->ttl   = max(1, $ttlSeconds);
    }

    public function get(string $key): ?array
    {
        $raw = $this->store->get($this->prefix() . 'e:' . $key);
        if ($raw === null) {
            return null;
        }
        $entry = json_decode($raw, true);
        if (!is_array($entry) || !array_key_exists('claims', $entry) || !isset($entry['until'])) {
            return null;
        }
        return ['claims' => is_array($entry['claims']) ? $entry['claims'] : null, 'until' => (int) $entry['until']];
    }

    public function put(string $key, ?array $claims, int $until): void
    {
        $ttl = max(1, $until - time());
        $this->store->put($this->prefix() . 'e:' . $key, (string) json_encode(['claims' => $claims, 'until' => $until]), $ttl);
        if ($claims === null) {
            return;
        }
        foreach (self::INDEXED as $field) {
            if (!isset($claims[$field]) || !is_scalar($claims[$field]) || (string) $claims[$field] === '') {
                continue;
            }
            $indexKey = $this->indexKey($field, (string) $claims[$field]);
            $list     = $this->readIndex($indexKey);
            if (!in_array($key, $list, true)) {
                $list[] = $key;
                $list   = array_slice($list, -self::INDEX_MAX);
                $this->store->put($indexKey, (string) json_encode($list), $this->ttl);
            }
        }
    }

    public function evict(string $field, string $value): int
    {
        $indexKey = $this->indexKey($field, $value);
        $evicted  = 0;
        foreach ($this->readIndex($indexKey) as $key) {
            $entry = $this->get($key);
            if ($entry !== null && $entry['claims'] !== null && (string) ($entry['claims'][$field] ?? '') === $value) {
                $this->store->delete($this->prefix() . 'e:' . $key);
                $evicted++;
            }
        }
        $this->store->delete($indexKey);
        return $evicted;
    }

    /** Starts a new key generation; old entries expire on their own. */
    public function clear(): void
    {
        $this->prefix = null;
        $this->store->put('nine:at:gen', bin2hex(random_bytes(6)), 0);
    }

    private function prefix(): string
    {
        if ($this->prefix === null) {
            $generation = $this->store->get('nine:at:gen') ?? '0';
            $this->prefix = 'nine:at:' . $generation . ':';
        }
        return $this->prefix;
    }

    private function indexKey(string $field, string $value): string
    {
        return $this->prefix() . 'i:' . $field . ':' . hash('sha256', $value);
    }

    /**
     * @return string[]
     */
    private function readIndex(string $indexKey): array
    {
        $list = json_decode((string) $this->store->get($indexKey), true);
        return is_array($list) ? array_values(array_filter($list, 'is_string')) : [];
    }
}
