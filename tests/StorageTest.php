<?php

namespace Nine\Tests;

use Nine\Storage\FileStorage;
use Nine\Storage\MemoryStorage;
use Nine\Storage\StorageInterface;
use PHPUnit\Framework\TestCase;

final class StorageTest extends TestCase
{
    /** @var string */
    private $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/nine-php-sdk-test-' . bin2hex(random_bytes(4)) . '.d';
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->dir . '/*') ?: []);
        @rmdir($this->dir);
    }

    /**
     * @return StorageInterface[]
     */
    private function stores(): array
    {
        return [new MemoryStorage(), new FileStorage($this->dir)];
    }

    public function testPutGetDelete(): void
    {
        foreach ($this->stores() as $store) {
            $store->put('nine:login:a/b.c', 'value');
            $this->assertSame('value', $store->get('nine:login:a/b.c'));
            $store->delete('nine:login:a/b.c');
            $this->assertNull($store->get('nine:login:a/b.c'));
        }
    }

    public function testExpiry(): void
    {
        foreach ($this->stores() as $store) {
            $store->put('k', 'v', 1);
            $this->assertSame('v', $store->get('k'));
        }
        sleep(2);
        $file = new FileStorage($this->dir);
        $this->assertNull($file->get('k'));
    }

    public function testFilesAreNotWorldReadable(): void
    {
        $store = new FileStorage($this->dir);
        $store->put('k', 'secret');
        foreach (glob($this->dir . '/*.nine') as $file) {
            $this->assertSame('0600', substr(sprintf('%o', fileperms($file)), -4));
        }
    }
}
