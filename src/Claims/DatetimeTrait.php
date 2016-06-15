<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Claims;

use DateTimeInterface;
use Tymon\JWTAuth\Support\Utils;
use Tymon\JWTAuth\Exceptions\InvalidClaimException;

trait DatetimeTrait
{
    /**
     * Set the claim value, and call a validate method.
     *
     * @param  mixed  $value
     *
     * @throws \Tymon\JWTAuth\Exceptions\InvalidClaimException
     *
     * @return $this
     */
    public function setValue($value)
    {
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
     *
     * @return bool
     */
    protected function isFuture($value)
    {
        return Utils::isFuture($value);
    }

    /**
     * Determine whether the value is in the past.
     *
     * @param  mixed  $value
     *
     * @return bool
     */
    protected function isPast($value)
    {
        return Utils::isPast($value);
    }
}
