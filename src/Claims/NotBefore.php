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

use function Tymon\JWTAuth\Support\now;
use Tymon\JWTAuth\Contracts\Claim as ClaimContract;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class NotBefore extends Claim
{
    use DatetimeTrait;

    /**
     * @var string
     */
    const NAME = 'nbf';

    /**
     * {@inheritdoc}
     */
    public function verify(): void
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException('Not Before (nbf) timestamp cannot be in the future');
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function make($value = null): ClaimContract
    {
        return new static($value ?? now()->getTimestamp());
    }
}
