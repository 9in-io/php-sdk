<?php

namespace Nine\Http;

use Nine\Exceptions\NineException;

/** Default transport (ext-curl). Redirects are not followed. */
final class CurlHttpClient implements HttpClientInterface
{
    /** @var int */
    private $timeout;

    /** @var string */
    private $userAgent;

    public function __construct(int $timeoutSeconds = 10, string $userAgent = '9in-php-sdk/3')
    {
        $this->timeout   = $timeoutSeconds;
        $this->userAgent = $userAgent;
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): Response
    {
        $handle = curl_init($url);

        $lines = ['User-Agent: ' . $this->userAgent];
        foreach ($headers as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }

        $responseHeaders = [];
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_HTTPHEADER     => $lines,
            CURLOPT_HEADERFUNCTION => function ($curl, $line) use (&$responseHeaders) {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return strlen($line);
            },
        ]);
        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }

        $result = curl_exec($handle);
        if ($result === false) {
            $error = curl_error($handle);
            throw new NineException('network_error', $error);
        }
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

        return new Response($status, $responseHeaders, (string) $result);
    }
}
