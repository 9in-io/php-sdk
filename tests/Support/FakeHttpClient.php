<?php

namespace Nine\Tests\Support;

use Nine\Http\HttpClientInterface;
use Nine\Http\Response;

/** Routes requests to closures keyed by "METHOD url-prefix" and records every call. */
final class FakeHttpClient implements HttpClientInterface
{
    /** @var array<string, callable> */
    private $routes = [];

    /** @var array<int, array{method: string, url: string, headers: array<string, string>, body: string|null}> */
    public $calls = [];

    public function on(string $method, string $urlPrefix, callable $handler): self
    {
        $this->routes[strtoupper($method) . ' ' . $urlPrefix] = $handler;
        return $this;
    }

    /**
     * @param array<string, mixed> $json
     */
    public function json(string $method, string $urlPrefix, array $json, int $status = 200): self
    {
        return $this->on($method, $urlPrefix, function () use ($json, $status) {
            return new Response($status, ['content-type' => 'application/json'], json_encode($json));
        });
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $this->calls[] = ['method' => strtoupper($method), 'url' => $url, 'headers' => $headers, 'body' => $body];
        $match         = null;
        foreach ($this->routes as $key => $handler) {
            [$routeMethod, $prefix] = explode(' ', $key, 2);
            if ($routeMethod === strtoupper($method) && strpos($url, $prefix) === 0 && ($match === null || strlen($prefix) > strlen($match[0]))) {
                $match = [$prefix, $handler];
            }
        }
        if ($match === null) {
            return new Response(404, [], '{"error":"not_found"}');
        }
        return ($match[1])($url, $headers, $body);
    }

    /**
     * @return array<int, array{method: string, url: string, headers: array<string, string>, body: string|null}>
     */
    public function callsTo(string $urlPrefix): array
    {
        return array_values(array_filter($this->calls, function ($call) use ($urlPrefix) {
            return strpos($call['url'], $urlPrefix) === 0;
        }));
    }
}
