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

use Tymon\JWTAuth\JWT;
use Tymon\JWTAuth\Builder;
use Tymon\JWTAuth\Manager;
use Tymon\JWTAuth\JWTGuard;
use Tymon\JWTAuth\Blacklist;
use Lcobucci\JWT\Parser as JWTParser;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Http\Parser\Cookies;
use Illuminate\Support\ServiceProvider;
use Lcobucci\JWT\Builder as JWTBuilder;
use Tymon\JWTAuth\Http\Middleware\Check;
use Tymon\JWTAuth\Providers\JWT\Lcobucci;
use Tymon\JWTAuth\Http\Parser\AuthHeaders;
use Tymon\JWTAuth\Http\Parser\InputSource;
use Tymon\JWTAuth\Http\Parser\QueryString;
use Tymon\JWTAuth\Http\Parser\RouteParams;
use Tymon\JWTAuth\Contracts\Providers\Auth;
use Tymon\JWTAuth\Contracts\Providers\Storage;
use Tymon\JWTAuth\Http\Middleware\Authenticate;
use Tymon\JWTAuth\Http\Middleware\RefreshToken;
use Tymon\JWTAuth\Console\JWTGenerateSecretCommand;
use Tymon\JWTAuth\Http\Middleware\AuthenticateAndRenew;
use Tymon\JWTAuth\Contracts\Providers\JWT as JWTContract;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * The middleware aliases.
     *
     * @var array
     */
    protected $middlewareAliases = [
        'jwt.auth' => Authenticate::class,
        'jwt.check' => Check::class,
        'jwt.refresh' => RefreshToken::class,
        'jwt.renew' => AuthenticateAndRenew::class,
    ];

    /**
     * Boot the service provider.
     */
    abstract public function boot();

    /**
     * Register the service provider.
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerJWTProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerBuilder();
        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJWT();
        $this->registerJWTCommand();

        $this->commands('tymon.jwt.secret');
    }

    /**
     * Extend Laravel's Auth.
     */
    protected function extendAuthGuard()
    {
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JwtGuard(
                $app['tymon.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard->useResponsable(version_compare($this->app->version(), '5.5', '>='));
        });
    }

    /**
     * Bind some aliases.
     */
    protected function registerAliases()
    {
        $this->app->alias('tymon.jwt', JWT::class);
        $this->app->alias('tymon.jwt.provider.jwt', JWTContract::class);
        $this->app->alias('tymon.jwt.provider.jwt.lcobucci', Lcobucci::class);
        $this->app->alias('tymon.jwt.provider.storage', Storage::class);
        $this->app->alias('tymon.jwt.builder', Builder::class);
        $this->app->alias('tymon.jwt.manager', Manager::class);
        $this->app->alias('tymon.jwt.blacklist', Blacklist::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     */
    protected function registerJWTProvider()
    {
        $this->registerLcobucciProvider();

        $this->app->singleton('tymon.jwt.provider.jwt', function ($app) {
            return $this->getConfigInstance('providers.jwt');
        });
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     */
    protected function registerLcobucciProvider()
    {
        $this->app->singleton('tymon.jwt.provider.jwt.lcobucci', function ($app) {
            return new Lcobucci(
                new JWTBuilder(),
                new JWTParser(),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Storage provider.
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('tymon.jwt.provider.storage', function () {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the JWT builder.
     */
    protected function registerBuilder()
    {
        $this->app->singleton('tymon.jwt.builder', function ($app) {
            $builder = new Builder($app['request']);

            $app->refresh('request', $builder, 'setRequest');

            return $builder->lockSubject($this->config('lock_subject'))
                           ->setTTL($this->config('ttl'))
                           ->setRequiredClaims($this->config('required_claims'))
                           ->setLeeway($this->config('leeway'))
                           ->setMaxRefreshPeriod($this->config('max_refresh_period'));
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     */
    protected function registerManager()
    {
        $this->app->singleton('tymon.jwt.manager', function ($app) {
            $manager = new Manager(
                $app['tymon.jwt.provider.jwt'],
                $app['tymon.jwt.blacklist']
            );

            return $manager->setBlacklistEnabled((bool) $this->config('blacklist_enabled'));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('tymon.jwt.parser', function ($app) {
            $parser = new Parser($app['request'], [
                'header' => new AuthHeaders,
                'query' => new QueryString,
                'input' => new InputSource,
                'route' => new RouteParams,
                'cookie' => new Cookies($this->config('decrypt_cookies')),
            ]);

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main JWT class.
     */
    protected function registerJWT()
    {
        $this->app->singleton('tymon.jwt', function ($app) {
            return new JWT(
                $app['tymon.jwt.builder'],
                $app['tymon.jwt.manager'],
                $app['tymon.jwt.parser']
            );
        });
    }

    /**
     * Register the bindings for the Blacklist.
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('tymon.jwt.blacklist', function ($app) {
            $blacklist = new Blacklist($app['tymon.jwt.provider.storage']);

            return $blacklist->setGracePeriod($this->config('blacklist_grace_period'));
        });
    }

    /**
     * Register the Artisan command.
     */
    protected function registerJWTCommand()
    {
        $this->app->singleton('tymon.jwt.secret', function () {
            return new JWTGenerateSecretCommand;
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param  mixed  $default
     *
     * @return mixed
     */
    protected function config(string $key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @return mixed
     */
    protected function getConfigInstance(string $key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
