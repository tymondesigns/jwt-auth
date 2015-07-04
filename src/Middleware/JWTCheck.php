<?php

namespace Tymon\JWTAuth\Middleware;

class JWTCheck extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     *
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        if ($token = $this->auth->setRequest($request)->getToken()) {
            try {
                $this->auth->authenticate();
            } catch (\Exception $e) {
                unset($e);
            }
        }

        return $next($request);
    }
}
