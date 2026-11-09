<?php

namespace Nine\Exceptions;

/**
 * Base exception. `getError()` is the machine-readable code (OAuth style, e.g.
 * `invalid_token`, `invalid_grant`, `not_found`), `getStatus()` the HTTP status when the
 * error came from (or maps to) an HTTP response.
 */
class NineException extends \RuntimeException
{
    /** @var string */
    protected $error;

    /** @var int|null */
    protected $status;

    public function __construct(string $error, ?string $description = null, ?int $status = null, ?\Throwable $previous = null)
    {
        parent::__construct($description ? "{$error}: {$description}" : $error, 0, $previous);
        $this->error  = $error;
        $this->status = $status;
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function getStatus(): ?int
    {
        return $this->status;
    }
}
