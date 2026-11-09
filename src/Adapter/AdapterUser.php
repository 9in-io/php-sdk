<?php

namespace Nine\Adapter;

/**
 * A user from your database, in the shape 9in expects (standard OIDC claim names).
 * `metadata` is passed through to tokens under the `app` claim.
 */
final class AdapterUser implements \JsonSerializable
{
    public const FIELDS = [
        'id', 'email', 'email_verified', 'phone_number', 'phone_number_verified', 'username', 'name',
        'given_name', 'family_name', 'picture', 'locale', 'zoneinfo', 'birthdate', 'blocked', 'metadata',
    ];

    /** @var array<string, mixed> */
    private $attributes;

    /**
     * @param array<string, mixed> $attributes keys from FIELDS; unknown keys are dropped
     */
    public function __construct(array $attributes)
    {
        if (!isset($attributes['id']) || (string) $attributes['id'] === '') {
            throw new \InvalidArgumentException('id is required');
        }
        $clean = array_intersect_key($attributes, array_flip(self::FIELDS));
        $clean['id'] = (string) $clean['id'];
        foreach (['email_verified', 'phone_number_verified', 'blocked'] as $flag) {
            if (array_key_exists($flag, $clean) && $clean[$flag] !== null) {
                $clean[$flag] = (bool) $clean[$flag];
            }
        }
        if (isset($clean['metadata']) && !is_array($clean['metadata'])) {
            $clean['metadata'] = null;
        }
        $this->attributes = $clean;
    }

    /**
     * @param array<string, mixed> $attributes
     */
    public static function make(array $attributes): self
    {
        return new self($attributes);
    }

    public function id(): string
    {
        return $this->attributes['id'];
    }

    public function isBlocked(): bool
    {
        return !empty($this->attributes['blocked']);
    }

    /**
     * @return mixed
     */
    public function get(string $field)
    {
        return $this->attributes[$field] ?? null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $out = $this->attributes;
        if (isset($out['metadata']) && $out['metadata'] === []) {
            $out['metadata'] = new \stdClass(); // JSON object, not []
        }
        return $out;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
