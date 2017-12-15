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

namespace Tymon\JWTAuth\Http\Middleware;

use Closure;
use Throwable;
use Illuminate\Http\Request;

class Check extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if ($this->auth->parser()->setRequest($request)->hasToken()) {
            try {
                $this->auth->parseToken()->authenticate();
            } catch (Throwable $e) {
                //
            }
        }

        return $next($request);
    }
}
