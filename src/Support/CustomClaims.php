<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Support;

trait CustomClaims
{
    /**
     * Custom claims.
     *
     * @var array
     */
    protected $customClaims = [];

    /**
     * Set the custom claims.
     *
     * @param  array  $customClaims
     *
     * @return $this
     */
    public function customClaims(array $customClaims)
    {
        $this->customClaims = $customClaims;

        return $this;
    }

    /**
     * Alias to set the custom claims.
     *
     * @param  array  $customClaims
     *
     * @return $this
     */
    public function claims(array $customClaims)
    {
        return $this->customClaims($customClaims);
    }

    /**
     * Get the custom claims.
     *
     * @return array
     */
    public function getCustomClaims()
    {
        return $this->customClaims;
    }
}
