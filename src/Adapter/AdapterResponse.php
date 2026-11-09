<?php

namespace Nine\Adapter;

/** Signed response to send back to 9in. */
final class AdapterResponse
{
    /** @var int */
    public $status;

    /** @var array<string, string> */
    public $headers;

    /** @var string */
    public $body;

    /**
     * @param array<string, string> $headers
     */
    public function __construct(int $status, array $headers, string $body)
    {
        $this->status  = $status;
        $this->headers = $headers;
        $this->body    = $body;
    }

    /** Sends it with PHP's SAPI functions (plain PHP; frameworks use the properties instead). */
    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $name => $value) {
            header("{$name}: {$value}");
        }
        echo $this->body;
    }
}
