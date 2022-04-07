<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use BadMethodCallException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\UserNotDefinedException;

class JWTGuard implements Guard
{
    use GuardHelpers, Macroable {
        __call as macroCall;
    }

    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;

    /**
     * The JWT instance.
     *
     * @var \Tymon\JWTAuth\JWT
     */
    protected $jwt;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Instantiate the class.
     *
     * @param  \Tymon\JWTAuth\JWT  $jwt
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public function __construct(JWT $jwt, UserProvider $provider, Request $request)
    {
        $this->jwt = $jwt;
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
        if ($this->user !== null) {
            return $this->user;
        }

        if ($this->jwt->setRequest($this->request)->getToken() &&
            ($payload = $this->jwt->check(true)) &&
            $this->validateSubject()
        ) {
            return $this->user = $this->provider->retrieveById($payload['sub']);
        }
    }

    /**
     * Get the currently authenticated user or throws an exception.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     *
     * @throws \Tymon\JWTAuth\Exceptions\UserNotDefinedException
     */
    public function userOrFail()
    {
        if (! $user = $this->user()) {
            throw new UserNotDefinedException;
        }

        return $user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return (bool) $this->attempt($credentials, false);
    }

    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @param  array  $credentials
     * @param  bool  $login
     * @return bool|string
     */
    public function attempt(array $credentials = [], $login = true)
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    /**
     * Create a token for a user.
     *
     * @param  \Tymon\JWTAuth\Contracts\JWTSubject  $user
     * @return string
     */
    public function login(JWTSubject $user)
    {
        $token = $this->jwt->fromUser($user);
        $this->setToken($token)->setUser($user);

        return $token;
    }

    /**
     * Logout the user, thus invalidating the token.
     *
     * @param  bool  $forceForever
     * @return void
     */
    public function logout($forceForever = false)
    {
        $this->requireToken()->invalidate($forceForever);

        $this->user = null;
        $this->jwt->unsetToken();
    }

    /**
     * Refresh the token.
     *
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     * @return string
     */
    public function refresh($forceForever = false, $resetClaims = false)
    {
        return $this->requireToken()->refresh($forceForever, $resetClaims);
    }

    /**
     * Invalidate the token.
     *
     * @param  bool  $forceForever
     * @return \Tymon\JWTAuth\JWT
     */
    public function invalidate($forceForever = false)
    {
        return $this->requireToken()->invalidate($forceForever);
    }

    /**
     * Create a new token by User id.
     *
     * @param  mixed  $id
     * @return string|null
     */
    public function tokenById($id)
    {
        if ($user = $this->provider->retrieveById($id)) {
            return $this->jwt->fromUser($user);
        }
    }

    /**
     * Log a user into the application using their credentials.
     *
     * @param  array  $credentials
     * @return bool
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
     * @param  mixed  $id
     * @return bool
     */
    public function onceUsingId($id)
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Alias for onceUsingId.
     *
     * @param  mixed  $id
     * @return bool
     */
    public function byId($id)
    {
        return $this->onceUsingId($id);
    }

    /**
     * Add any custom claims.
     *
     * @param  array  $claims
     * @return $this
     */
    public function claims(array $claims)
    {
        $this->jwt->claims($claims);

        return $this;
    }

    /**
     * Get the raw Payload instance.
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function getPayload()
    {
        return $this->requireToken()->getPayload();
    }

    /**
     * Alias for getPayload().
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function payload()
    {
        return $this->getPayload();
    }

    /**
     * Set the token.
     *
     * @param  \Tymon\JWTAuth\Token|string  $token
     * @return $this
     */
    public function setToken($token)
    {
        $this->jwt->setToken($token);

        return $this;
    }

    /**
     * Set the token ttl.
     *
     * @param  int  $ttl
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->jwt->factory()->setTTL($ttl);

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
     * @return $this
     */
    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;

        return $this;
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
     * @return \Illuminate\Http\Request
     */
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }

    /**
     * Set the current request instance.
     *
     * @param  \Illuminate\Http\Request  $request
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
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Ensure the JWTSubject matches what is in the token.
     *
     * @return bool
     */
    protected function validateSubject()
    {
        // If the provider doesn't have the necessary method
        // to get the underlying model name then allow.
        if (! method_exists($this->provider, 'getModel')) {
            return true;
        }

        return $this->jwt->checkSubjectModel($this->provider->getModel());
    }

    /**
     * Ensure that a token is available in the request.
     *
     * @return \Tymon\JWTAuth\JWT
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function requireToken()
    {
        if (! $this->jwt->setRequest($this->getRequest())->getToken()) {
            throw new JWTException('Token could not be parsed from the request.');
        }

        return $this->jwt;
    }

    /**
     * Magically call the JWT instance.
     *
     * @param  string  $method
     * @param  array  $parameters
     * @return mixed
     *
     * @throws \BadMethodCallException
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
