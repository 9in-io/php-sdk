<?php

namespace Nine\Exceptions;

/** The sign-in callback does not match a login started by this application. */
class InvalidStateException extends NineException
{
    public function __construct(?string $description = 'unknown or expired state')
    {
        parent::__construct('invalid_state', $description, 400);
    }
}
