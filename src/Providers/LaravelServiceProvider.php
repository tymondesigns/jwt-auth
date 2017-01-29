<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers;

use Tymon\JWTAuth\Http\Middleware\Check;
use Tymon\JWTAuth\Http\Middleware\Authenticate;
use Tymon\JWTAuth\Http\Middleware\RefreshToken;
use Tymon\JWTAuth\Http\Middleware\AuthenticateAndRenew;

class LaravelServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $path = realpath(__DIR__.'/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->aliasMiddleware('jwt.auth', Authenticate::class);
        $this->aliasMiddleware('jwt.refresh', RefreshToken::class);
        $this->aliasMiddleware('jwt.renew', AuthenticateAndRenew::class);
        $this->aliasMiddleware('jwt.check', Check::class);

        $this->extendAuthGuard();
    }

    /**
     * Register a middleware alias.
     *
     * @param  string $name
     * @param  string $class
     *
     * @return \Illuminate\Routing\Router
     */
    protected function aliasMiddleware($name, $class)
    {
        $router = $this->app['router'];

        // the method name was changed in Laravel 5.4
        if (method_exists($router, 'aliasMiddleware')) {
            return $router->aliasMiddleware($name, $class);
        }

        return $router->middleware($name, $class);
    }
}
