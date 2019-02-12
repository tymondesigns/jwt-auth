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

use Tymon\JWTAuth\Contracts\Claim as ClaimContract;
use Illuminate\Support\Collection as IlluminateCollection;

class Collection extends IlluminateCollection
{
    /**
     * Get a Claim instance by it's unique name.
     */
    public function getByClaimName(string $name, ...$args): ?ClaimContract
    {
        return $this->filter->matchesName($name)
            ->first(...$args);
    }

    /**
     * Verify the validity of each claim.
     */
    public function verify(): self
    {
        $this->each->verify();

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

        return (new static($claims))
            ->diff($this->keys())
            ->isEmpty();
    }

    /**
     * Get the claims as key/val array.
     */
    public function toPlainArray(): array
    {
        return $this->map->getValue()
            ->toArray();
    }

    /**
     * {@inheritdoc}
     */
    protected function getArrayableItems($items): array
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
