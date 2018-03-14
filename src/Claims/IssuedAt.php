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

use Tymon\JWTAuth\Support\Utils;
use Tymon\JWTAuth\Exceptions\InvalidClaimException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class IssuedAt extends Claim
{
    use DatetimeTrait {
        validateCreate as commonValidateCreate;
    }

    /**
     * {@inheritdoc}
     */
    protected $name = 'iat';

    /**
     * {@inheritdoc}
     */
    public function validateCreate($value)
    {
        $this->commonValidateCreate($value);

        if ($this->isFuture($value)) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }

    /**
     * {@inheritdoc}
     */
    public function validatePayload()
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException('Issued At (iat) timestamp cannot be in the future');
        }

        if ($this->maxRefreshPeriod !== null) {
            $max = Utils::timestamp($this->getValue())->addMinutes($this->maxRefreshPeriod);
            if ($max->greaterThanOrEqualTo(Utils::now())) {
                throw new TokenExpiredException('Token has expired');
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function make($value = null): Claim
    {
        return new static($value ?? Utils::now()->getTimestamp());
    }
}
