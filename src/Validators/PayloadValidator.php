<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends Validator
{
    /**
     * Run the validations on the payload array.
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenExpiredException
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public static function check(Collection $claims, array $requiredClaims = []): Collection
    {
        if (! $claims->hasAllClaims($requiredClaims)) {
            throw new TokenInvalidException('JWT does not contain the required claims');
        }

        return $claims->validate();
    }
}
