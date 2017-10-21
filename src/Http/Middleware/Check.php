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
use Exception;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\PayloadException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;

class Check extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if ($this->auth->parser()->setRequest($request)->hasToken()) {
            try {
                $this->auth->parseToken()->authenticate();
            } catch (Exception $e) {
                if ($exception instanceof TokenInvalidException) {
                    throw new TokenInvalidException();
                } elseif ($exception instanceof TokenExpiredException) {
                    throw new TokenExpiredException();
                } elseif ($exception instanceof TokenBlacklistedException) {
                    throw new TokenBlacklistedException();
                } elseif ($exception instanceof PayloadException) {
                    throw new PayloadException();
                } else {
                    throw new JWTException('unknown issue');
                }
            }
        } else {
            throw new JWTException('no token');
        }

        return $next($request);
    }
}
