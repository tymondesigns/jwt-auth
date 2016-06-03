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
     * Determine whether the value is numeric
     *
     * @param  mixed  $value
     *
     * @return bool
     */
    protected function checkNumeric($value)
    {
        return is_numeric($value);
    }

    /**
     * Determine whether the value is not in the future
     *
     * @param  mixed  $value
     *
     * @return bool
     */
    protected function checkNotFuture($value)
    {
        return $this->checkNumeric($value) && ! Utils::isFuture($value);
    }

    /**
     * Determine whether the value is not in the past
     *
     * @param  mixed  $value
     *
     * @return bool
     */
    protected function checkNotPast($value)
    {
        return $this->checkNumeric($value) && ! Utils::isPast($value);
    }

    /**
     * Validate the claim.
     *
     * @param  mixed  $value
     *
     * @return bool
     */
    public function validate($value)
    {
        return $this->checkNumeric($value);
    }
}
