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
        $path = realpath(__DIR__ . '/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->bootBindings();

        $this->commands('tymon.jwt.generate');
    }

    /**
     * Bind some Interfaces and implementations
     */
    protected function bootBindings()
    {
        $this->app['Tymon\JWTAuth\JWTAuth'] = function ($app) {
            return $app['tymon.jwt.auth'];
        };

        $this->app['Tymon\JWTAuth\Providers\JWT\JWTInterface'] = function ($app) {
            return $app['tymon.jwt.provider.jwt'];
        };

        $this->app['Tymon\JWTAuth\Providers\Auth\AuthInterface'] = function ($app) {
            return $app['tymon.jwt.provider.auth'];
        };

        $this->app['Tymon\JWTAuth\Providers\Storage\StorageInterface'] = function ($app) {
            return $app['tymon.jwt.provider.storage'];
        };

        $this->app['Tymon\JWTAuth\JWTManager'] = function ($app) {
            return $app['tymon.jwt.manager'];
        };

        $this->app['Tymon\JWTAuth\Blacklist'] = function ($app) {
            return $app['tymon.jwt.blacklist'];
        };

        $this->app['Tymon\JWTAuth\PayloadFactory'] = function ($app) {
            return $app['tymon.jwt.payload.factory'];
        };

        $this->app['Tymon\JWTAuth\Claims\Factory'] = function ($app) {
            return $app['tymon.jwt.claim.factory'];
        };

        $this->app['Tymon\JWTAuth\Validators\PayloadValidator'] = function ($app) {
            return $app['tymon.jwt.validators.payload'];
        };
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        // register providers
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
     * Register the bindings for the JSON Web Token provider
     */
    protected function registerJWTProvider()
    {
        $this->app['tymon.jwt.provider.jwt'] = $this->app->share(function ($app) {
            $provider = $this->config('providers.jwt');

            return $app->make($provider, [$this->config('secret'), $this->config('algo')]);
        });
    }

    /**
     * Register the bindings for the Auth provider
     */
    protected function registerAuthProvider()
    {
        $this->app['tymon.jwt.provider.auth'] = $this->app->share(function ($app) {
            return $this->getConfigInstance('providers.auth');
        });
    }

    /**
     * Register the bindings for the Storage provider
     */
    protected function registerStorageProvider()
    {
        $this->app['tymon.jwt.provider.storage'] = $this->app->share(function ($app) {
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
        $this->app['tymon.jwt.manager'] = $this->app->share(function ($app) {

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
        $this->app['tymon.jwt.parser'] = $this->app->share(function ($app) {
            return new TokenParser($app['request']);
        });
    }

    /**
     * Register the bindings for the main JWTAuth class
     */
    protected function registerJWTAuth()
    {
        $this->app['tymon.jwt.auth'] = $this->app->share(function ($app) {
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
        $this->app['tymon.jwt.blacklist'] = $this->app->share(function ($app) {
            $instance = new Blacklist($app['tymon.jwt.provider.storage']);

            return $instance->setGracePeriod($this->config('blacklist_grace_period'));
        });
    }

    /**
     * Register the bindings for the payload validator
     */
    protected function registerPayloadValidator()
    {
        $this->app['tymon.jwt.validators.payload'] = $this->app->share(function () {
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
        $this->app['tymon.jwt.payload.factory'] = $this->app->share(function ($app) {
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
        $this->app['tymon.jwt.generate'] = $this->app->share(function () {
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
