<?php

namespace Tymon\JWTAuth\Providers\Auth;

use Exception;
use Tymon\JWTAuth\Contracts\Providers\Auth;
use Cartalyst\Sentinel\Sentinel as SentinelAuth;

class Sentinel implements Auth
{
    /**
     * @var \Cartalyst\Sentinel\Sentinel
     */
    protected $sentinel;

    /**
     * @param \Cartalyst\Sentinel\Sentinel  $sentinel
     */
    public function __construct(SentinelAuth $sentinel)
    {
        $this->sentinel = $sentinel;
    }

    /**
     * Check a user's credentials
     *
     * @param  array  $credentials
     *
     * @return boolean
     */
    public function byCredentials(array $credentials = [])
    {
        return $this->sentinel->stateless($credentials);
    }

    /**
     * Authenticate a user via the id
     *
     * @param  mixed  $id
     *
     * @return boolean
     */
    public function byId($id)
    {
        if ($user = $this->sentinel->getUserRepository()->findById($id)) {
            $this->sentinel->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Get the currently authenticated user
     *
     * @return mixed
     */
    public function user()
    {
        return $this->sentinel->getUser();
    }
}
