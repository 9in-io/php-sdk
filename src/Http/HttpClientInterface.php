<?php

namespace Nine\Http;

/**
 * Minimal HTTP transport so the SDK has no hard dependency on an HTTP library.
 * Implement it to route calls through Guzzle, Symfony HttpClient, a PSR-18 client, or a
 * test double.
 */
interface HttpClientInterface
{
    /**
     * @param array<string, string> $headers
     */
    public function request(string $method, string $url, array $headers = [], ?string $body = null): Response;
}
