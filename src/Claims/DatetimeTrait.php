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

use DateInterval;
use DateTimeInterface;
use Tymon\JWTAuth\Support\Utils;
use Tymon\JWTAuth\Contracts\Claim;
use Tymon\JWTAuth\Exceptions\InvalidClaimException;

trait DatetimeTrait
{
    /**
     * Time leeway in seconds.
     *
     * @var int
     */
    protected $leeway = 0;

    /**
     * Max refresh period in minutes.
     *
     * @var int|null
     */
    protected $maxRefreshPeriod;

    /**
     * Set the claim value, and call a validate method.
     *
     * @param  mixed  $value
     *
     * @throws \Tymon\JWTAuth\Exceptions\InvalidClaimException
     */
    public function setValue($value): Claim
    {
        if ($value instanceof DateInterval) {
            $value = Utils::now()->add($value);
        }

        if ($value instanceof DateTimeInterface) {
            $value = $value->getTimestamp();
        }

        return parent::setValue($value);
    }

    /**
     * {@inheritdoc}
     */
    public function validateCreate($value)
    {
        if (! is_numeric($value)) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }

    /**
     * Determine whether the value is in the future.
     *
     * @param  mixed  $value
     */
    protected function isFuture($value): bool
    {
        return Utils::isFuture($value, $this->leeway);
    }

    /**
     * Determine whether the value is in the past.
     *
     * @param  mixed  $value
     */
    protected function isPast($value): bool
    {
        return Utils::isPast($value, $this->leeway);
    }

    /**
     * Set the leeway in seconds.
     */
    public function setLeeway(int $leeway): self
    {
        $this->leeway = $leeway;

        return $this;
    }

    /**
     * Set the max refresh period in minutes.
     *
     * @param int|null $period
     */
    public function setMaxRefreshPeriod(?int $period): self
    {
        $this->maxRefreshPeriod = $period;

        return $this;
    }
}
