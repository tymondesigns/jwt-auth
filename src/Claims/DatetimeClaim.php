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

abstract class DatetimeClaim extends Claim
{
    /**
     * {@inheritdoc}
     */
    public function setValue($value)
    {
        if ($value instanceof DateTimeInterface) {
            $value = $value->getTimestamp();
        }

        return parent::setValue($value);
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
        return is_numeric($value);
    }
}
