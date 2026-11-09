<?php

namespace Nine\Tests;

use Nine\EventDeduplicator;
use Nine\Storage\FileStorage;
use Nine\Storage\MemoryStorage;
use PHPUnit\Framework\TestCase;

final class EventDeduplicatorTest extends TestCase
{
    public function testProcessesEachEventOnce(): void
    {
        $dedupe = new EventDeduplicator(new MemoryStorage());
        $calls  = 0;
        $handle = function () use (&$calls) {
            return ++$calls;
        };

        $this->assertSame(['status' => EventDeduplicator::PROCESSED, 'result' => 1], $dedupe->process('evt_1', $handle));
        $this->assertSame(EventDeduplicator::DUPLICATE, $dedupe->process('evt_1', $handle)['status']);
        $this->assertSame(EventDeduplicator::PROCESSED, $dedupe->process('evt_2', $handle)['status']);
        $this->assertSame(2, $calls);
    }

    public function testReleasesTheIdWhenTheHandlerFails(): void
    {
        $dedupe = new EventDeduplicator(new MemoryStorage());
        try {
            $dedupe->process('evt_1', function () {
                throw new \RuntimeException('db down');
            });
            $this->fail('expected the exception');
        } catch (\RuntimeException $e) {
            $this->assertSame('db down', $e->getMessage());
        }
        $this->assertSame(EventDeduplicator::PROCESSED, $dedupe->process('evt_1', function () {
            return true;
        })['status']);
    }

    public function testReportsConcurrentDeliveriesAsInProgress(): void
    {
        $store  = new MemoryStorage();
        $dedupe = new EventDeduplicator($store);
        $inner  = null;
        $dedupe->process('evt_1', function () use ($dedupe, &$inner) {
            $inner = $dedupe->process('evt_1', function () {
                return 'never';
            });
        });
        $this->assertSame(EventDeduplicator::IN_PROGRESS, $inner['status']);
    }

    public function testFileStorageAddIsExclusive(): void
    {
        $dir   = sys_get_temp_dir() . '/nine-dedupe-' . bin2hex(random_bytes(4));
        $store = new FileStorage($dir);
        try {
            $this->assertTrue($store->add('k', 'a', 60));
            $this->assertFalse($store->add('k', 'b', 60));
            $this->assertSame('a', $store->get('k'));
            $store->put('expired', 'x', 1);
            sleep(2);
            $this->assertTrue($store->add('expired', 'y', 60));
            $this->assertSame('y', $store->get('expired'));
        } finally {
            array_map('unlink', glob($dir . '/*') ?: []);
            @rmdir($dir);
        }
    }
}
