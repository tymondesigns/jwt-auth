<?php

namespace Tymon\JWTAuth\Providers;

class LaravelServiceProvider extends JWTAuthServiceProvider
{
    /**
     * Boot the service provider.
     */
    public function boot()
    {
        $this->setupConfig();
        $this->commands('tymon.jwt.generate');
    }

    /**
     * Setup the config
     */
    protected function setupConfig()
    {
        $path = realpath(__DIR__ . '/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');
    }
}