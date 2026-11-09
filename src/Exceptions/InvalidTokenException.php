<?php

namespace Nine\Exceptions;

/** The access or ID token is missing, malformed, expired, or not signed by the tenant. */
class InvalidTokenException extends NineException
{
    public function __construct(?string $description = null, ?\Throwable $previous = null)
    {
        parent::__construct('invalid_token', $description, 401, $previous);
    }
}
