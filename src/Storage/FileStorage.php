<?php

namespace Nine\Storage;

/**
 * One file per key under a directory you own (not world-readable). add() is atomic on a
 * local filesystem (exclusive create); use a shared store when several servers process
 * the same events.
 */
final class FileStorage implements AtomicStorageInterface
{
    /** @var string */
    private $directory;

    public function __construct(string $directory)
    {
        $this->directory = rtrim($directory, DIRECTORY_SEPARATOR);
        if (!is_dir($this->directory)) {
            mkdir($this->directory, 0700, true);
        }
    }

    public function put(string $key, string $value, int $ttl = 0): void
    {
        $payload = json_encode(['expires' => $ttl > 0 ? time() + $ttl : 0, 'value' => $value]);
        $path    = $this->path($key);
        $tmp     = $path . '.' . bin2hex(random_bytes(4));
        file_put_contents($tmp, $payload, LOCK_EX);
        chmod($tmp, 0600);
        rename($tmp, $path);
    }

    public function add(string $key, string $value, int $ttl = 0): bool
    {
        $path = $this->path($key);
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $handle = @fopen($path, 'x');
            if ($handle !== false) {
                fwrite($handle, (string) json_encode(['expires' => $ttl > 0 ? time() + $ttl : 0, 'value' => $value]));
                fclose($handle);
                chmod($path, 0600);
                return true;
            }
            if ($this->get($key) !== null) {
                return false; // present and not expired
            }
            // get() removed an expired entry: try once more
        }
        return false;
    }

    public function get(string $key): ?string
    {
        $path = $this->path($key);
        if (!is_file($path)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($path), true);
        if (!is_array($data) || !isset($data['value'])) {
            return null;
        }
        if ($data['expires'] > 0 && $data['expires'] <= time()) {
            @unlink($path);
            return null;
        }
        return (string) $data['value'];
    }

    public function delete(string $key): void
    {
        @unlink($this->path($key));
    }

    /** Removes expired entries. */
    public function cleanup(): void
    {
        foreach (glob($this->directory . DIRECTORY_SEPARATOR . '*.nine') ?: [] as $file) {
            $data = json_decode((string) @file_get_contents($file), true);
            if (!is_array($data) || ($data['expires'] > 0 && $data['expires'] <= time())) {
                @unlink($file);
            }
        }
    }

    private function path(string $key): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.nine';
    }
}
