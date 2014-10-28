<?php

namespace Tymon\JWTAuth\Auth;

use Illuminate\Auth\AuthManager;

class IlluminateAuthAdapter implements AuthInterface
{

    /**
     * @var \Illuminate\Auth\AuthManager
     */
    protected $auth;

    /**
     * @param \Illuminate\Auth\AuthManager $auth
     */
    public function __construct(AuthManager $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param  array $credentials
     * @return bool
     */
    public function check(array $credentials = [])
    {
        return $this->auth->once($credentials);
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param  mixed $id
     * @return bool
     */
    public function checkUsingId($id)
    {
        return $this->auth->onceUsingId($id);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return mixed
     */
    public function user()
    {
        return $this->auth->user();
    }
}
