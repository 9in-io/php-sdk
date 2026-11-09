<?php

namespace Nine\Exceptions;

/** A `9in-signature` header is missing, malformed, expired or does not match. */
class SignatureException extends NineException
{
    /** @var string missing | malformed | expired | mismatch */
    private $reason;

    public function __construct(string $reason = 'mismatch', string $description = 'signature verification failed')
    {
        parent::__construct('invalid_signature', $description . " ({$reason})", 401);
        $this->reason = $reason;
    }

    public function getReason(): string
    {
        return $this->reason;
    }
}
