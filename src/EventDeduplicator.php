<?php

namespace Nine;

use Nine\Storage\AtomicStorageInterface;

/**
 * Processes each webhook (or adapter) event at most once. 9in keeps the event id on every
 * retry and redelivery and retries until it gets a 2xx, for about a day.
 *
 *   $outcome = (new EventDeduplicator($store))->process($event['id'], function () use ($event) {
 *       // handle the event
 *   });
 *   http_response_code($outcome['status'] === EventDeduplicator::IN_PROGRESS ? 409 : 204);
 *
 * - processed: first delivery, handler succeeded → answer 2xx.
 * - duplicate: already processed → answer 2xx so 9in stops retrying.
 * - in_progress: another delivery of the same event is still running → answer 409 so 9in
 *   tries again later.
 * - The handler threw: the id is released and the exception rethrown → answer 5xx so 9in retries.
 */
final class EventDeduplicator
{
    public const PROCESSED   = 'processed';
    public const DUPLICATE   = 'duplicate';
    public const IN_PROGRESS = 'in_progress';

    /** @var AtomicStorageInterface */
    private $store;

    /** @var int */
    private $ttl;

    /** @var int */
    private $lock;

    /** @var string */
    private $prefix;

    /**
     * @param int $ttlSeconds  how long a processed id is remembered (default 3 days)
     * @param int $lockSeconds how long a running handler holds the id (default 300)
     */
    public function __construct(AtomicStorageInterface $store, int $ttlSeconds = 259200, int $lockSeconds = 300, string $prefix = 'nine:event:')
    {
        $this->store  = $store;
        $this->ttl    = $ttlSeconds;
        $this->lock   = $lockSeconds;
        $this->prefix = $prefix;
    }

    /**
     * @return array{status: string, result: mixed}
     * @throws \Throwable whatever the handler throws
     */
    public function process(string $eventId, callable $handler): array
    {
        if ($eventId === '') {
            throw new \InvalidArgumentException('event id required');
        }
        $key = $this->prefix . $eventId;

        if (!$this->store->add($key, 'processing', $this->lock)) {
            return ['status' => $this->store->get($key) === 'done' ? self::DUPLICATE : self::IN_PROGRESS, 'result' => null];
        }

        try {
            $result = $handler();
        } catch (\Throwable $e) {
            $this->store->delete($key);
            throw $e;
        }

        $this->store->put($key, 'done', $this->ttl);

        return ['status' => self::PROCESSED, 'result' => $result];
    }
}
