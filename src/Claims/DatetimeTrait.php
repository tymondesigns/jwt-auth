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
use Carbon\Carbon;
use DateTimeInterface;
use Carbon\CarbonInterval;
use function Tymon\JWTAuth\Support\now;
use function Tymon\JWTAuth\Support\is_past;
use function Tymon\JWTAuth\Support\is_future;
use function Tymon\JWTAuth\Support\timestamp;
use Tymon\JWTAuth\Contracts\Claim as ClaimContract;
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
    public function setValue($value): ClaimContract
    {
        if ($value instanceof DateInterval) {
            $value = now()->add($value);
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
     */
    protected function isFuture(int $value): bool
    {
        return is_future($value, $this->leeway);
    }

    /**
     * Determine whether the value is in the past.
     */
    protected function isPast(int $value): bool
    {
        return is_past($value, $this->leeway);
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
     * Get the leeway.
     */
    public function getLeeway(): int
    {
        return $this->leeway;
    }

    /**
     * Set the max refresh period in minutes.
     */
    public function setMaxRefreshPeriod(?int $period): self
    {
        $this->maxRefreshPeriod = $period;

        return $this;
    }

    /**
     * Get the max refresh period.
     */
    public function getMaxRefreshPeriod(): ?int
    {
        return $this->maxRefreshPeriod;
    }

    /**
     * Get the claim value as a Carbon instance.
     */
    public function asCarbon(): Carbon
    {
        return timestamp($this->getValue());
    }

    /**
     * Get the claim value as a CarbonInterval instance.
     */
    public function asCarbonInterval(): CarbonInterval
    {
        return now()->diffAsCarbonInterval($this->asCarbon());
    }
}
