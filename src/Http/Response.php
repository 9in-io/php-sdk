<?php

namespace Nine\Http;

final class Response
{
    /** @var int */
    public $status;

    /** @var array<string, string> header name (lower case) => value */
    public $headers;

    /** @var string */
    public $body;

    /**
     * @param array<string, string> $headers
     */
    public function __construct(int $status, array $headers = [], string $body = '')
    {
        $this->status  = $status;
        $this->headers = array_change_key_case($headers, CASE_LOWER);
        $this->body    = $body;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function ok(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    /**
     * @return array<string, mixed>
     */
    public function json(): array
    {
        if ($this->body === '') {
            return [];
        }
        $decoded = json_decode($this->body, true);
        return is_array($decoded) ? $decoded : [];
    }
}
