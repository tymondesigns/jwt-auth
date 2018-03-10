<?php

declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Claims;

use Illuminate\Support\Collection as IlluminateCollection;

class Collection extends IlluminateCollection
{
    /**
     * Constructor.
     */
    public function __construct($items = [])
    {
        parent::__construct($this->getArrayableItems($items));
    }

    /**
     * Get a Claim instance by it's unique name.
     *
     * @return \Tymon\JWTAuth\Claims\Claim
     */
    public function getByClaimName(string $name, callable $callback = null, $default = null)
    {
        return $this->filter(function (Claim $claim) use ($name) {
            return $claim->getName() === $name;
        })->first($callback, $default);
    }

    /**
     * Validate each claim under a given context.
     *
     * @return $this
     */
    public function validate()
    {
        $this->each(function ($claim) {
            $claim->validatePayload();
        });

        return $this;
    }

    /**
     * Determine if the Collection contains all of the given keys.
     *
     * @param  mixed  $claims
     */
    public function hasAllClaims($claims): bool
    {
        if (empty($claims)) {
            return true;
        }

        return (new static($claims))->diff($this->keys())->isEmpty();
    }

    /**
     * Get the claims as key/val array.
     */
    public function toPlainArray(): array
    {
        return $this->map(function (Claim $claim) {
            return $claim->getValue();
        })->toArray();
    }

    /**
     * {@inheritdoc}
     */
    protected function getArrayableItems($items)
    {
        return $this->sanitizeClaims($items);
    }

    /**
     * Ensure that the given claims array is keyed by the claim name.
     *
     * @param  mixed  $items
     */
    private function sanitizeClaims($items): array
    {
        $claims = [];
        foreach ($items as $key => $value) {
            if (! is_string($key) && $value instanceof Claim) {
                $key = $value->getName();
            }

            $claims[$key] = $value;
        }

        return $claims;
    }
}
