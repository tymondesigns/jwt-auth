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

namespace Tymon\JWTAuth;

use Illuminate\Support\Arr;

final class Options
{
    /**
     * @var array
     */
    protected $options = [];

    /**
     * Options constructor.
     */
    public function __construct(array $options = [])
    {
        $this->options = $options;
    }

    /**
     * Get the required claims.
     */
    public function requiredClaims(): array
    {
        return Arr::get($this->options, 'required_claims', []);
    }

    /**
     * Get the leeway.
     */
    public function leeway(): int
    {
        return Arr::get($this->options, 'leeway', 0);
    }

    /**
     * Get the maximum refresh period.
     */
    public function maxRefreshPeriod(): ?int
    {
        return Arr::get($this->options, 'max_refresh_period');
    }

    /**
     * Get the custom validators.
     */
    public function validators(): array
    {
        return Arr::get($this->options, 'validators', []);
    }
}
