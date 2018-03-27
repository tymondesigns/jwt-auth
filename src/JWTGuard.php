<?php

declare(strict_types=1);

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
use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Tymon\JWTAuth\Http\TokenResponse;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Contracts\Auth\UserProvider;
use Tymon\JWTAuth\Exceptions\UserNotDefinedException;

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
     * The flag to use the Laravel Responsable interface.
     *
     * @var bool
     */
    protected $useResponsable = true;

    /**
     * Instantiate the class.
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

        if (($payload = $this->getPayload()) && $this->validateSubject($payload)) {
            return $this->user = $this->provider->retrieveById($payload['sub']);
        }
    }

    /**
     * Get the currently authenticated user or throws an exception.
     *
     * @throws \Tymon\JWTAuth\Exceptions\UserNotDefinedException
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
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
     */
    public function validate(array $credentials = []): bool
    {
        return (bool) $this->attempt($credentials, false);
    }

    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @return bool|Token
     */
    public function attempt(array $credentials = [], bool $login = true)
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
     * @return \Tymon\JWTAuth\Http\TokenResponse|\Tymon\JWTAuth\Token
     */
    public function login(JWTSubject $user)
    {
        $token = $this->jwt->fromUser($user);
        $this->setToken($token)->setUser($user);

        return $this->tokenResponse($token);
    }

    /**
     * Logout the user, thus invalidating the token.
     */
    public function logout()
    {
        $this->requireToken()->invalidate();

        $this->user = null;
        $this->jwt->unsetToken();
    }

    /**
     * Refresh the token.
     *
     * @return \Tymon\JWTAuth\Http\TokenResponse|\Tymon\JWTAuth\Token
     */
    public function refresh()
    {
        $token = $this->requireToken()->refresh();

        return $this->tokenResponse($token);
    }

    /**
     * Invalidate the token.
     */
    public function invalidate(): self
    {
        $this->requireToken()->invalidate();

        return $this;
    }

    /**
     * Create a new token by User id.
     *
     * @param  mixed  $id
     *
     * @return \Tymon\JWTAuth\Token|null
     */
    public function tokenById($id)
    {
        if ($user = $this->provider->retrieveById($id)) {
            return $this->jwt->fromUser($user);
        }
    }

    /**
     * Log a user into the application using their credentials.
     */
    public function once(array $credentials = []): bool
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
     */
    public function onceUsingId($id): bool
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
     */
    public function byId($id): bool
    {
        return $this->onceUsingId($id);
    }

    /**
     * Add any custom claims.
     */
    public function claims(array $claims): self
    {
        $this->jwt->claims($claims);

        return $this;
    }

    /**
     * Get the payload.
     */
    public function payload(): Payload
    {
        return $this->requireToken()->payload();
    }

    /**
     * Set the token.
     *
     * @param  \Tymon\JWTAuth\Token|string  $token
     */
    public function setToken($token): self
    {
        $this->jwt->setToken($token);

        return $this;
    }

    /**
     * Set the token ttl.
     */
    public function setTTL(int $ttl): self
    {
        $this->jwt->builder()->setTTL($ttl);

        return $this;
    }

    /**
     * Get the user provider used by the guard.
     */
    public function getProvider(): UserProvider
    {
        return $this->provider;
    }

    /**
     * Set the user provider used by the guard.
     */
    public function setProvider(UserProvider $provider): self
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
     */
    public function getRequest(): Request
    {
        return $this->request ?? Request::createFromGlobals();
    }

    /**
     * Set the current request instance.
     */
    public function setRequest(Request $request): self
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
     * Get the responsable Token.
     *
     * @return \Tymon\JWTAuth\Http\TokenResponse|\Tymon\JWTAuth\Token
     */
    protected function tokenResponse(Token $token)
    {
        return $this->useResponsable
            ? new TokenResponse($token, $this->jwt->getTTL())
            : $token;
    }

    /**
     * Get the payload from a token that may exist in the request.
     *
     * @return \Tymon\JWTAuth\Payload|null
     */
    protected function getPayload()
    {
        if ($this->jwt->setRequest($this->request)->getToken()) {
            return $this->jwt->check(true);
        }
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     */
    protected function hasValidCredentials($user, array $credentials): bool
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Ensure the JWTSubject matches what is in the token.
     *
     * @param  \Tymon\JWTAuth\Payload|null  $payload
     */
    protected function validateSubject($payload = null): bool
    {
        // If the provider doesn't have the necessary method
        // to get the underlying model name then allow.
        if (! method_exists($this->provider, 'getModel')) {
            return true;
        }

        return $this->jwt->checkSubjectModel($this->provider->getModel(), $payload);
    }

    /**
     * Ensure that a token is available in the request.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function requireToken(): JWT
    {
        if (! $this->jwt->setRequest($this->getRequest())->getToken()) {
            throw new JWTException('Token could not be parsed from the request.');
        }

        return $this->jwt;
    }

    /**
     * Determine whether to use Laravel Responsable interface.
     */
    public function useResponsable(bool $use = true): self
    {
        $this->useResponsable = $use;

        return $this;
    }

    /**
     * Magically call the JWT instance.
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call(string $method, array $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
