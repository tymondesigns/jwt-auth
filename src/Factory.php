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

use Tymon\JWTAuth\Claims\Claim;
use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Validators\PayloadValidator;
use Tymon\JWTAuth\Claims\Factory as ClaimFactory;

class Factory
{
    /**
     * Create a Payload instance.
     */
    public static function make(array $claims = [], ?Options $options = null): Payload
    {
        $collection = Collection::make($claims)
            ->map(function ($value, $key) use ($options) {
                if ($value instanceof Claim) {
                    return $value;
                }

                return is_string($key)
                    ? ClaimFactory::get($key, $value, $options)
                    : ClaimFactory::get($value, null, $options);
            });

        // Validate the claims
        $collection = PayloadValidator::check($collection, $options);

        return new Payload($collection);
    }
}
