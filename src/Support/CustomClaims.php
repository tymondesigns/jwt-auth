<?php

namespace Tymon\JWTAuth\Support;

trait CustomClaims
{
    /**
     * Custom claims
     *
     * @var array
     */
    protected $customClaims = [];

    /**
     * Set the custom claims.
     *
     * @param array $customClaims
     *
     * @return self
     */
    public function customClaims(array $customClaims)
    {
        $this->customClaims = $customClaims;

        return $this;
    }
}
