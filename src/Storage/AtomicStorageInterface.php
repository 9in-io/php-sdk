<?php

namespace Nine\Storage;

/** A store that can insert a key only when it is absent (needed by EventDeduplicator). */
interface AtomicStorageInterface extends StorageInterface
{
    /**
     * Stores `$value` only when `$key` is absent or expired. Must be atomic across the
     * processes that share the store.
     *
     * @return bool true when stored
     */
    public function add(string $key, string $value, int $ttl = 0): bool;
}
