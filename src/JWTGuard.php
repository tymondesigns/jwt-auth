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

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\ForwardsCalls;
use Illuminate\Support\Traits\Macroable;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Events\JWTAttempt;
use Tymon\JWTAuth\Events\JWTInvalidate;
use Tymon\JWTAuth\Events\JWTLogin;
use Tymon\JWTAuth\Events\JWTLogout;
use Tymon\JWTAuth\Events\JWTRefresh;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\UserNotDefinedException;
use Tymon\JWTAuth\Http\TokenResponse;

class JWTGuard implements Guard
{
    use GuardHelpers;
    use ForwardsCalls;
    use Macroable {
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
     */
    protected JWT $jwt;

    /**
     * The request instance.
     */
    protected Request $request;

    /**
     * The flag to use the Laravel Responsable interface.
     */
    protected bool $useResponsable = true;

    /**
     * The Dispatcher instance.
     */
    protected Dispatcher $events;

    /**
     * Constructor.
     */
    public function __construct(JWT $jwt, UserProvider $provider, Request $request, Dispatcher $events)
    {
        $this->jwt = $jwt;
        $this->provider = $provider;
        $this->request = $request;
        $this->events = $events;
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
            return $this->user = $this->provider->retrieveById($payload[Subject::NAME]);
        }
    }

    /**
     * Get the currently authenticated user or throws an exception.
     *
     * @throws \Tymon\JWTAuth\Exceptions\UserNotDefinedException
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
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

        $this->events->dispatch(new JWTAttempt($user));

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

        $this->events->dispatch(
            new JWTLogin($user, $token)
        );

        return $this->tokenResponse($token);
    }

    /**
     * Logout the user, thus invalidating the token.
     */
    public function logout(): void
    {
        $this->requireToken()->invalidate();

        $this->events->dispatch(
            new JWTLogout($this->user, $this->jwt)
        );

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

        $this->events->dispatch(
            new JWTRefresh($this->user, $token)
        );

        return $this->tokenResponse($token);
    }

    /**
     * Invalidate the token.
     */
    public function invalidate(): self
    {
        $this->requireToken()->invalidate();

        $this->events->dispatch(
            new JWTInvalidate($this->user, $this->jwt)
        );

        return $this;
    }

    /**
     * Create a new token by User id.
     *
     * @param  mixed  $id
     */
    public function tokenById($id): ?Token
    {
        return ($user = $this->provider->retrieveById($id))
            ? $this->jwt->fromUser($user)
            : null;
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
    public function setTTL(?int $ttl): self
    {
        $this->jwt->setTTL($ttl);

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
     */
    protected function getPayload(): ?Payload
    {
        if ($this->jwt->setRequest($this->request)->getToken() === null) {
            return null;
        }

        return $this->jwt->check(true) ?: null;
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
     */
    protected function validateSubject(?Payload $payload = null): bool
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
        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        return $this->forwardCallTo($this->jwt, $method, $parameters);
    }
}
