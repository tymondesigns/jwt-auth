<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers;

use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Claims\Factory as ClaimFactory;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;
use Tymon\JWTAuth\Contracts\Providers\Auth;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Contracts\Providers\Storage;
use Tymon\JWTAuth\Http\TokenParser;
use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Manager;
use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Validators\PayloadValidator;

class LumenServiceProvider extends ServiceProvider
{
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

        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerPayloadFactory();
        $this->registerJWTCommand();

        $this->commands('tymon.jwt.generate');
    }

    /**
     * Bind some Interfaces and implementations
     */
    protected function registerAliases()
    {
        $this->app->alias('tymon.jwt.auth', JWTAuth::class);
        $this->app->alias('tymon.jwt.provider.jwt', JWT::class);
        $this->app->alias('tymon.jwt.provider.auth', Auth::class);
        $this->app->alias('tymon.jwt.provider.storage', Storage::class);
        $this->app->alias('tymon.jwt.manager', Manager::class);
        $this->app->alias('tymon.jwt.blacklist', Blacklist::class);
        $this->app->alias('tymon.jwt.payload.factory', Factory::class);
        $this->app->alias('tymon.jwt.validators.payload', PayloadValidator::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider
     */
    protected function registerJWTProvider()
    {
        $this->app->singleton('tymon.jwt.provider.jwt', function ($app) {
            $provider = $this->config('providers.jwt');

            return $app->make($provider, [$this->config('secret'), $this->config('algo'), $this->config('cert')]);
        });
    }

    /**
     * Register the bindings for the Auth provider
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('tymon.jwt.provider.auth', function () {
            return $this->getConfigInstance('providers.auth');
        });
    }

    /**
     * Register the bindings for the Storage provider
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('tymon.jwt.provider.storage', function () {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the JWT Manager
     */
    protected function registerManager()
    {
        $this->app->singleton('tymon.jwt.manager', function ($app) {

            $instance = new Manager(
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

            return $instance->setGracePeriod($this->config('blacklist_grace_period'))
                            ->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('tymon.jwt.validators.payload', function () {
            return (new PayloadValidator)
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
            $factory = new Factory(
                new ClaimFactory,
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
        $this->app->singleton('tymon.jwt.generate', function () {
            return new JWTGenerateCommand();
        });
    }

    /**
     * Helper to get the config values
     *
     * @param  string $key
     *
     * @return mixed
     */
    protected function config($key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance. Pinched from dingo/api :)
     *
     * @param  string  $key
     *
     * @return mixed
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
