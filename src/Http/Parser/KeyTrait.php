<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Http\Parser;

trait KeyTrait
{
    /**
     * The key.
     *
     * @var string
     */
    protected $key = 'token';

    /**
     * Set the key.
     */
    public function setKey(string $key): self
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Get the key.
     */
    public function getKey(): string
    {
        return $this->key;
    }
}
