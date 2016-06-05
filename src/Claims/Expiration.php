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

use Tymon\JWTAuth\Exceptions\InvalidClaimException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

class Expiration extends Claim
{
    use DatetimeTrait;

    /**
     * The claim name.
     *
     * @var string
     */
    protected $name = 'exp';

    /**
     * {@inheritdoc}
     */
    public function validateCreate($value)
    {
        if (! is_numeric($value)) {
            throw new InvalidClaimException('Invalid value provided for claim "'.$this->getName().'": '.$value);
        }

        return $value;
    }

    /**
     * {@inheritdoc}
     */
    public function validatePayload()
    {
        if ($this->isPast($this->getValue())) {
            throw new TokenExpiredException('Token has expired');
        }
    }
}
