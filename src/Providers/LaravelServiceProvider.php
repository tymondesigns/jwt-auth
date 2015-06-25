<?php

namespace Tymon\JWTAuth\Providers;

class LaravelServiceProvider extends LumenServiceProvider
{
    /**
     * Boot the service provider.
     */
    public function boot()
    {
        $path = realpath(__DIR__ . '/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');
    }
}