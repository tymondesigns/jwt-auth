<?php

namespace Tymon\JWTAuth;

trait RefreshFlow
{
    /**
     * @var bool
     */
    protected $refreshFlow = false;

    /**
     * Set the refresh flow flag
     *
     * @param  bool  $refreshFlow
     *
     * @return self
     */
    public function setRefreshFlow($refreshFlow = true)
    {
        $this->refreshFlow = $refreshFlow;

        return $this;
    }
}
