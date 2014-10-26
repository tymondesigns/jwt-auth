<?php namespace Tymon\JWTAuth;

use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;
use Tymon\JWTAuth\JWTAuthFilter;
use Tymon\JWTAuth\Auth\IlluminateAuth;

class JWTAuthServiceProvider extends ServiceProvider {

    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Boot the service provider.
     */
    public function boot()
    {
        $this->package('tymon/jwt-auth', 'jwt');

        $this->bootBindings();

        // register the command
        $this->commands('tymon.jwt.generate');

        // register the filter
        $this->app['router']->filter('jwt-auth', 'tymon.jwt.filter');
    }

    /**
     * Bind some Interfaces and implementations
     */
    protected function bootBindings()
    {
        $this->app['Tymon\JWTAuth\JWTAuth'] = function ($app) {
            return $app['tymon.jwt.auth'];
        };

        $this->app['Tymon\JWTAuth\Providers\ProviderInterface'] = function ($app) {
            return $app['tymon.jwt.provider'];
        };

        $this->app['Tymon\JWTAuth\Auth\AuthInterface'] = function ($app) {
            return $app['tymon.jwt.illuminate.auth'];
        };
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerJWTAuth();
        $this->registerJWTAuthFilter();
        $this->registerJWTCommand();
    }

    /**
     * Register the bindings for the JSON Web Token provider
     */
    protected function registerJWTProvider()
    {
        $this->app['tymon.jwt.provider'] = $this->app->share(function ($app) {
            $secret = $this->config('secret');
            $ttl = $this->config('ttl');
            $algo = $this->config('algo');
            $provider = $this->config('provider');

            $instance = $app->make($provider, [ $secret, $app['request'] ]);

            return $instance->setTTL($ttl)->setAlgo($algo);
        });
    }

    /**
     * Register the bindings for the JSON Web Token provider
     */
    protected function registerAuthProvider()
    {
        $this->app['tymon.jwt.illuminate.auth'] = $this->app->share(function ($app) {
            return new IlluminateAuth($app['auth']);
        });
    }

    /**
     * Register the bindings for the main JWTAuth class
     */
    protected function registerJWTAuth()
    {
        $this->app['tymon.jwt.auth'] = $this->app->share(function ($app) {
            $identifier = $this->config('identifier');
            $user = $this->config('user');

            $userInstance = $app->make($user);
            $auth = new JWTAuth( $userInstance, $app['tymon.jwt.provider'], $auth, $app['request'] );

            return $auth->setIdentifier($identifier);
        });
    }

    /**
     * Register the bindings for the 'jwt-auth' filter
     */
    protected function registerJWTAuthFilter()
    {
        $this->app['tymon.jwt.filter'] = $this->app->share(function ($app) {
            return new JWTAuthFilter($app['events'], $app['tymon.jwt.auth']);
        });
    }

    /**
     * Register the Artisan command
     */
    protected function registerJWTCommand()
    {
        $this->app['tymon.jwt.generate'] = $this->app->share(function($app) {
            return new JWTGenerateCommand($app['files']);
        });
    }

    /**
     * Helper to get the config values
     */
    protected function config($key, $default = null)
    {
        $this->app['config']->get("jwt::$key", $default);
    }

    /**
     * Get the services provided by the provider.
     *
     * @return string[]
     */
    public function provides()
    {
        return [
            'tymon.jwt.provider',
            'tymon.jwt.auth',
            'tymon.jwt.generate',
            'tymon.jwt.filter',
            'Tymon\JWTAuth\Providers\ProviderInterface',
            'Tymon\JWTAuth\JWTAuth'
        ];
    }

}
