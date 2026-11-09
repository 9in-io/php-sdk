<?php

namespace Nine\TokenCache;

/** @internal Cached introspection answers of HybridTokenVerifier, keyed by token hash. */
interface AnswerCacheInterface
{
    /**
     * @return array{claims: array<string, mixed>|null, until: int}|null
     */
    public function get(string $key): ?array;

    /**
     * @param array<string, mixed>|null $claims null caches a refusal
     * @param int                       $until  unix seconds
     */
    public function put(string $key, ?array $claims, int $until): void;

    /** Removes the answers whose claim `$field` (jti, sid or sub) equals `$value`; returns how many. */
    public function evict(string $field, string $value): int;

    public function clear(): void;
}
