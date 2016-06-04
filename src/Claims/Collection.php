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

use Illuminate\Support\Str;
use Illuminate\Support\Collection as IlluminateCollection;

class Collection extends IlluminateCollection
{
    /**
     * Get a Claim instance by it's unique name.
     *
     * @return \Tymon\JWTAuth\Claims\Claim
     */
    public function getByClaimName($name)
    {
        return $this->filter(function ($claim) use ($name) {
            return $claim->getName() === $name;
        })->first();
    }

    /**
     * Validate each claim under a given context.
     *
     * @param  string  $context
     *
     * @return $this
     */
    public function validate($context = 'payload')
    {
        $this->each(function ($claim) {
            call_user_func_array(
                [$claim, 'validate'.Str::ucfirst($context)],
                array_shift(func_get_arg())
            );
        });

        return $this;
    }

    /**
     * Get the claims as key/val array.
     *
     * @return array
     */
    public function toPlainArray()
    {
        return $this->map(function ($claim) {
            return $claim->getValue();
        })->toArray();
    }
}
