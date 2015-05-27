<?php

namespace Tymon\JWTAuth\Providers;

use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\JWTManager;
use Tymon\JWTAuth\PayloadFactory;
use Tymon\JWTAuth\Claims\Factory;
use Tymon\JWTAuth\Http\TokenParser;
use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;
use Tymon\JWTAuth\Validators\PayloadValidator;

class JWTAuthServiceProvider extends ServiceProvider
{
    /**
     * Boot the service provider.
     */
    public function boot()
    {
        $path = realpath(__DIR__ . '/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->commands('tymon.jwt.generate');
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerClaimFactory();
        $this->registerJWTManager();
        $this->registerTokenParser();

        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerPayloadFactory();
        $this->registerJWTCommand();
    }

    /**
     * Bind some Interfaces and implementations
     */
    protected function registerAliases()
    {
        $this->app->alias('tymon.jwt.auth', 'Tymon\JWTAuth\JWTAuth');
        $this->app->alias('tymon.jwt.provider.jwt', 'Tymon\JWTAuth\Providers\JWT\JWTInterface');
        $this->app->alias('tymon.jwt.provider.auth', 'Tymon\JWTAuth\Providers\Auth\AuthInterface');
        $this->app->alias('tymon.jwt.provider.storage', 'Tymon\JWTAuth\Providers\Storage\StorageInterface');
        $this->app->alias('tymon.jwt.manager', 'Tymon\JWTAuth\JWTManager');
        $this->app->alias('tymon.jwt.blacklist', 'Tymon\JWTAuth\Blacklist');
        $this->app->alias('tymon.jwt.payload.factory', 'Tymon\JWTAuth\PayloadFactory');
        $this->app->alias('tymon.jwt.claim.factory', 'Tymon\JWTAuth\Claims\Factory');
        $this->app->alias('tymon.jwt.validators.payload', 'Tymon\JWTAuth\Validators\PayloadValidator');
    }

    /**
     * Register the bindings for the JSON Web Token provider
     */
    protected function registerJWTProvider()
    {
        $this->app->singleton('tymon.jwt.provider.jwt', function ($app) {
            $provider = $this->config('providers.jwt');

            return $app->make($provider, [$this->config('secret'), $this->config('algo')]);
        });
    }

    /**
     * Register the bindings for the Auth provider
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('tymon.jwt.provider.auth', function ($app) {
            return $this->getConfigInstance('providers.auth');
        });
    }

    /**
     * Register the bindings for the Storage provider
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('tymon.jwt.provider.storage', function ($app) {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the Payload Factory
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('tymon.jwt.claim.factory', function () {
            return new Factory();
        });
    }

    /**
     * Register the bindings for the JWT Manager
     */
    protected function registerJWTManager()
    {
        $this->app->singleton('tymon.jwt.manager', function ($app) {

            $instance = new JWTManager(
                $app['tymon.jwt.provider.jwt'],
                $app['tymon.jwt.blacklist'],
                $app['tymon.jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'));
        });
    }

    /**
     * Register the bindings for the Token Parser
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('tymon.jwt.parser', function ($app) {
            return new TokenParser($app['request']);
        });
    }

    /**
     * Register the bindings for the main JWTAuth class
     */
    protected function registerJWTAuth()
    {
        $this->app->singleton('tymon.jwt.auth', function ($app) {
            return new JWTAuth(
                $app['tymon.jwt.manager'],
                $app['tymon.jwt.provider.auth'],
                $app['tymon.jwt.parser']
            );
        });
    }

    /**
     * Register the bindings for the main JWTAuth class
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('tymon.jwt.blacklist', function ($app) {
            $instance = new Blacklist($app['tymon.jwt.provider.storage']);

            return $instance->setGracePeriod($this->config('blacklist_grace_period'));
        });
    }

    /**
     * Register the bindings for the payload validator
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('tymon.jwt.validators.payload', function ($app) {
            return with(new PayloadValidator())
                ->setRefreshTTL($this->config('refresh_ttl'))
                ->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Payload Factory
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('tymon.jwt.payload.factory', function ($app) {
            $factory = new PayloadFactory(
                $app['tymon.jwt.claim.factory'],
                $app['request'],
                $app['tymon.jwt.validators.payload']
            );

            return $factory->setTTL($this->config('ttl'));
        });
    }

    /**
     * Register the Artisan command
     */
    protected function registerJWTCommand()
    {
        $this->app->singleton('tymon.jwt.generate', function ($app) {
            return new JWTGenerateCommand();
        });
    }

    /**
     * Helper to get the config values
     *
     * @param  string $key
     * @return string
     */
    protected function config($key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance. Pinched from dingo/api :)
     *
     * @param  string  $key
     * @return object
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_callable($instance)) {
            return call_user_func($instance, $this->app);
        } elseif (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
