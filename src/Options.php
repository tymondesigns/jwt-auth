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
     * @var string
     */
    const LEEWAY = 'leeway';

    /**
     * @var string
     */
    const REQUIRED_CLAIMS = 'required_claims';

    /**
     * @var string
     */
    const MAX_REFRESH_PERIOD = 'max_refresh_period';

    /**
     * @var string
     */
    const VALIDATORS = 'validators';

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
        return Arr::get($this->options, static::REQUIRED_CLAIMS, []);
    }

    /**
     * Get the leeway.
     */
    public function leeway(): int
    {
        return Arr::get($this->options, static::LEEWAY, 0);
    }

    /**
     * Get the maximum refresh period.
     */
    public function maxRefreshPeriod(): ?int
    {
        return Arr::get($this->options, static::MAX_REFRESH_PERIOD);
    }

    /**
     * Get the custom validators.
     */
    public function validators(): array
    {
        return Arr::get($this->options, static::VALIDATORS, []);
    }
}
