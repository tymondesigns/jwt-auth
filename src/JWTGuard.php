<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class JWTGuard implements Guard
{
    use GuardHelpers;

    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;

    /**
     * The JWTAuth instance.
     *
     * @var \Tymon\JWTAuth\JWTAuth
     */
    protected $auth;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    public function __construct(JWTAuth $auth, UserProvider $provider, Request $request)
    {
        $this->auth = $auth;
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (! is_null($this->user)) {
            return $this->user;
        }

        if (! $this->requireToken()->check()) {
            return null;
        }

        $id = $this->auth->getPayload()->get('sub');

        return $this->user = $this->provider->retrieveById($id);
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array $credentials
     *
     * @return boolean
     */
    public function validate(array $credentials = [])
    {
        return $this->attempt($credentials, false);
    }

    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @param  array  $credentials
     *
     * @return boolean
     */
    public function attempt(array $credentials = [], $login = true)
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {

            if ($login) {
                $this->setUser($user);

                return $this->auth->fromUser($user);
            }

            return true;
        }

        return false;
    }

    /**
     * Logout the user, thus invalidating the token.
     *
     * @param  boolean  $forceForever
     *
     * @return void
     */
    public function logout($forceForever = false)
    {
        $this->requireToken()->invalidate($forceForever);

        $this->user = null;
        $this->auth->unsetToken();
    }

    /**
     * Refresh the token
     *
     * @return  string
     */
    public function refresh()
    {
        return $this->requireToken()->refresh();
    }

    /**
     * Create a new token by User id
     *
     * @param   mixed  $id
     *
     * @return  string|null
     */
    public function tokenById($id)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            return $this->auth->fromUser($user);
        }

        return null;
    }

    /**
     * Log a user into the application using their credentials.
     *
     * @param  array $credentials
     *
     * @return boolean
     */
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given User into the application.
     *
     * @param  mixed $id
     *
     * @return boolean
     */
    public function onceUsingId($id)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Alias for onceUsingId
     *
     * @param   mixed  $id
     *
     * @return  boolean
     */
    public function byId($id)
    {
        return $this->onceUsingId($id);
    }

    /**
     * Get the raw Payload instance.
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function getPayload()
    {
        return $this->auth->getPayload();
    }

    /**
     * Set the token.
     *
     * @param  Token|string  $token
     *
     * @return JWTGuard
     */
    public function setToken($token)
    {
        $this->auth->setToken($token);

        return $this;
    }

    /**
     * Get the user provider used by the guard.
     *
     * @return \Illuminate\Contracts\Auth\UserProvider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Set the user provider used by the guard.
     *
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     *
     * @return void
     */
    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;
    }

    /**
     * Return the currently cached user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get the current request instance.
     *
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }

    /**
     * Set the current request instance.
     *
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the last user we attempted to authenticate.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     *
     * @return boolean
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Ensure that a token is available in the request
     *
     * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     *
     * @return \Tymon\JWTAuth\JWTAuth
     */
    protected function requireToken()
    {
        if (! $this->auth->getToken()) {
            throw new BadRequestHttpException($e->getMessage());
        }

        return $this->auth;
    }
}
