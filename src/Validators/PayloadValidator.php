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

use Illuminate\Support\Arr;
use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Options;
use Tymon\JWTAuth\Payload;

class PayloadValidator extends Validator
{
    /**
     * Run the validations on the payload array.
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenExpiredException
     * @throws \Tymon\JWTAuth\Exceptions\TokenInvalidException
     */
    public static function check(Collection $claims, ?Options $options = null): Payload
    {
        $options ??= new Options();

        if (! static::hasRequiredClaims($claims, $options)) {
            static::throwFailed('JWT does not contain the required claims');
        }

        // Run the built in verifications
        $claims->verify();

        // Run any custom validators
        foreach ($options->validators() as $name => $validator) {
            if ($claim = $claims->getByClaimName($name)) {
                if ($validator($claim->getValue(), $name) === false) {
                    static::throwFailed('Validation failed for claim ['.$name.']');
                }
            }
        }

        return new Payload($claims);
    }

    /**
     * Determine whether the given collection of claims has all the required claims.
     */
    protected static function hasRequiredClaims(Collection $claims, ?Options $options = null): bool
    {
        // If the collection doesn't have an exp then remove it from the required claims.
        $requiredClaims = $claims->has(Expiration::NAME)
            ? $options->requiredClaims()
            : Arr::except($options->requiredClaims(), [Expiration::NAME]);

        return $claims->hasAllClaims($requiredClaims);
    }
}
