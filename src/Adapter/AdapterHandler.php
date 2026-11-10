<?php

namespace Nine\Adapter;

use Nine\Signature;

/**
 * Framework-independent handler for adapter protocol v2. Mount it at your adapter base
 * URL; it serves `<base>/authenticate`, `<base>/user` and `<base>/event`:
 *
 *   $handler  = new AdapterHandler(getenv('NINE_ADAPTER_SECRET'), new MyUserAdapter());
 *   $response = $handler->handle($_SERVER['REQUEST_METHOD'], parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), getallheaders(), file_get_contents('php://input'));
 *   $response->send();
 *
 * Requests must carry a valid `9in-signature` (HMAC over timestamp, method, path and raw
 * body). Every response is signed over `<path>#<9in-request-id>` so 9in can reject a
 * response that was replayed from another request.
 */
final class AdapterHandler
{
    /** @var string[] */
    private $secrets;

    /** @var AdapterInterface */
    private $adapter;

    /** @var int */
    private $tolerance;

    /**
     * @param string|string[] $secret adapter secret from the console (Connections → User database).
     *                                Pass several during rotation; responses are signed with the first.
     */
    public function __construct($secret, AdapterInterface $adapter, int $toleranceSeconds = Signature::DEFAULT_TOLERANCE)
    {
        $this->secrets = array_values(array_filter((array) $secret, function ($value) {
            return is_string($value) && $value !== '';
        }));
        if (!$this->secrets) {
            throw new \InvalidArgumentException('an adapter secret is required');
        }
        $this->adapter   = $adapter;
        $this->tolerance = $toleranceSeconds;
    }

    /**
     * @param string                              $path    the request path exactly as 9in called it (no query string)
     * @param array<string, string|string[]>      $headers request headers (any case)
     */
    public function handle(string $method, string $path, array $headers, string $body): AdapterResponse
    {
        $headers   = array_change_key_case($headers, CASE_LOWER);
        $signature = self::header($headers, Signature::HEADER);
        $requestId = (string) self::header($headers, Signature::REQUEST_ID_HEADER);

        if (strtoupper($method) !== 'POST') {
            return new AdapterResponse(405, ['Allow' => 'POST', 'Content-Type' => 'text/plain'], 'Method not allowed');
        }
        if (!Signature::verify($this->secrets, $signature, 'POST', $path, $body, $this->tolerance)) {
            return new AdapterResponse(401, ['Content-Type' => 'application/json'], '{"error":"invalid_signature"}');
        }

        $input = $body === '' ? [] : json_decode($body, true);
        if (!is_array($input)) {
            return $this->respond($path, $requestId, 400, ['error' => 'invalid_json']);
        }

        $route = substr($path, strrpos($path, '/') + 1);
        switch ($route) {
            case 'authenticate':
                $identifier = self::identifier($input['identifier'] ?? null);
                if ($identifier === null || !isset($input['password']) || !is_string($input['password'])) {
                    return $this->respond($path, $requestId, 400, ['error' => 'invalid_request']);
                }
                $result = $this->adapter->authenticate($identifier, $input['password']);
                if ($result === AdapterInterface::BLOCKED || ($result instanceof AdapterUser && $result->isBlocked())) {
                    return $this->respond($path, $requestId, 403, ['error' => 'blocked']);
                }
                if (!$result instanceof AdapterUser) {
                    return $this->respond($path, $requestId, 401, ['error' => 'invalid_credentials']);
                }
                return $this->respond($path, $requestId, 200, ['user' => $result]);

            case 'user':
                if (isset($input['id']) && is_scalar($input['id']) && (string) $input['id'] !== '') {
                    $query = ['id' => (string) $input['id']];
                } elseif (($identifier = self::identifier($input['identifier'] ?? null)) !== null) {
                    $query = ['identifier' => $identifier];
                } else {
                    return $this->respond($path, $requestId, 400, ['error' => 'invalid_request']);
                }
                $user = $this->adapter->findUser($query);
                return $user
                    ? $this->respond($path, $requestId, 200, ['user' => $user])
                    : $this->respond($path, $requestId, 404, ['error' => 'not_found']);

            case 'event':
                if (!isset($input['event_type']) || !is_string($input['event_type'])) {
                    return $this->respond($path, $requestId, 400, ['error' => 'invalid_request']);
                }
                $input['data'] = isset($input['data']) && is_array($input['data']) ? $input['data'] : [];
                $this->adapter->onEvent($input);
                return $this->respond($path, $requestId, 204, null);
        }

        return $this->respond($path, $requestId, 404, ['error' => 'not_found']);
    }

    /**
     * @param mixed $payload
     */
    private function respond(string $path, string $requestId, int $status, $payload): AdapterResponse
    {
        $text    = $payload === null ? '' : json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $headers = [Signature::HEADER => Signature::sign($this->secrets[0], 'POST', $path . '#' . $requestId, $text)];
        if ($text !== '') {
            $headers['Content-Type'] = 'application/json';
        }
        return new AdapterResponse($status, $headers, $text);
    }

    /**
     * @param mixed $value
     * @return array{type: string, value: string}|null
     */
    private static function identifier($value): ?array
    {
        if (!is_array($value) || !isset($value['type'], $value['value']) || !is_string($value['value']) || $value['value'] === '') {
            return null;
        }
        if (!in_array($value['type'], ['email', 'username', 'phone'], true)) {
            return null;
        }
        return ['type' => $value['type'], 'value' => $value['value']];
    }

    /**
     * @param array<string, string|string[]> $headers
     */
    private static function header(array $headers, string $name): ?string
    {
        $value = $headers[$name] ?? null;
        if (is_array($value)) {
            $value = $value[0] ?? null;
        }
        return $value === null ? null : (string) $value;
    }
}
