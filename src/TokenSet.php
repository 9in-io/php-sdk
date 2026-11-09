<?php

namespace Nine;

use Nine\Jwt\Jwt;

/** Tokens returned by the token endpoint. Serialise with toArray() to keep them in a session. */
final class TokenSet
{
    /** @var string */
    public $accessToken;

    /** @var string|null */
    public $idToken;

    /** @var string|null */
    public $refreshToken;

    /** @var int unix seconds */
    public $expiresAt;

    /** @var string */
    public $scope;

    /** @var string|null where the app wanted to go when the login started */
    public $returnTo;

    public function __construct(string $accessToken, ?string $idToken, ?string $refreshToken, int $expiresAt, string $scope = '', ?string $returnTo = null)
    {
        $this->accessToken  = $accessToken;
        $this->idToken      = $idToken;
        $this->refreshToken = $refreshToken;
        $this->expiresAt    = $expiresAt;
        $this->scope        = $scope;
        $this->returnTo     = $returnTo;
    }

    /**
     * @param array<string, mixed> $response token endpoint JSON
     */
    public static function fromTokenResponse(array $response, ?TokenSet $previous = null): self
    {
        return new self(
            (string) $response['access_token'],
            isset($response['id_token']) ? (string) $response['id_token'] : ($previous ? $previous->idToken : null),
            isset($response['refresh_token']) ? (string) $response['refresh_token'] : ($previous ? $previous->refreshToken : null),
            time() + (int) ($response['expires_in'] ?? 3600),
            (string) ($response['scope'] ?? ($previous ? $previous->scope : '')),
            $previous ? $previous->returnTo : null
        );
    }

    public function isExpired(int $leewaySeconds = 60): bool
    {
        return $this->expiresAt - $leewaySeconds <= time();
    }

    /**
     * Claims of the ID token (verified when the tokens were received), or [] without one.
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return $this->idToken ? Jwt::claims($this->idToken) : [];
    }

    /**
     * @return array{access_token: string, id_token: string|null, refresh_token: string|null, expires_at: int, scope: string, return_to: string|null}
     */
    public function toArray(): array
    {
        return [
            'access_token'  => $this->accessToken,
            'id_token'      => $this->idToken,
            'refresh_token' => $this->refreshToken,
            'expires_at'    => $this->expiresAt,
            'scope'         => $this->scope,
            'return_to'     => $this->returnTo,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            (string) $data['access_token'],
            $data['id_token'] ?? null,
            $data['refresh_token'] ?? null,
            (int) $data['expires_at'],
            (string) ($data['scope'] ?? ''),
            $data['return_to'] ?? null
        );
    }
}
