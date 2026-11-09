<?php

namespace Nine\Exceptions;

/** The token is valid but lacks a required scope. */
class InsufficientScopeException extends NineException
{
    public function __construct(?string $description = null)
    {
        parent::__construct('insufficient_scope', $description, 403);
    }
}
