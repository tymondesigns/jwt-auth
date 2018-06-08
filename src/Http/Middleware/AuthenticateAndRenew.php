<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Http\Middleware;

use Closure;
use Tymon\JWTAuth\JWTGuard;
use Illuminate\Auth\AuthenticationException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Illuminate\Contracts\Auth\Factory as AuthFactory;

class AuthenticateAndRenew
{
    /**
     * Refresh period in seconds.
     *
     * @var int
     */
    public $refreshPeriod;

    /**
     * The authentication factory instance.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     */
    public function __construct(AuthFactory $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string[]  ...$guards
     *
     * @throws \Illuminate\Auth\AuthenticationException
     *
     * @return mixed
     */
    public function handle($request, Closure $next, ...$guards)
    {
        $this->authenticate($guards);

        $response = $next($request);

        $guard = $this->auth->guard();

        if (! $guard instanceof JWTGuard || $response->headers->has('Authorization')) {
            return $response;
        }

        return $this->setAuthenticationHeader($response, $guard);
    }

    /**
     * Determine if the user is logged in to any of the given guards.
     *
     * @param  array  $guards
     *
     * @throws \Illuminate\Auth\AuthenticationException
     *
     * @return void
     */
    protected function authenticate(array $guards)
    {
        if (empty($guards)) {
            return $this->auth->authenticate();
        }

        foreach ($guards as $guard) {
            if ($this->auth->guard($guard)->check()) {
                return $this->auth->shouldUse($guard);
            }
        }

        throw new AuthenticationException('Unauthenticated.', $guards);
    }

    /**
     * Set the authentication header.
     *
     * @param  \Illuminate\Http\Response|\Illuminate\Http\JsonResponse  $response
     * @param  \Tymon\JWTAuth\JWTGuard  $guard
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    protected function setAuthenticationHeader($response, $guard)
    {
        $period = $this->getRefreshPeriod();
        $expire = $guard->getPayload()->get('exp');

        if (! $expire || ($period && $expire - time() > $period)) {
            return $response;
        }

        try {
            $token = $guard->refresh();

            $response->headers->set('Authorization', "Bearer {$token}");
        } catch (TokenExpiredException $e) {
            // do nothing
        }

        return $response;
    }

    /**
     * Get refresh period.
     *
     * @return int
     */
    protected function getRefreshPeriod()
    {
        if (null === $this->refreshPeriod) {
            $this->refreshPeriod = intval(config('jwt.refresh_period'));
        }

        return $this->refreshPeriod;
    }
}
