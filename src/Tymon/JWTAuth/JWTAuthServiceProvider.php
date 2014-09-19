<?php namespace Tymon\JWTAuth;

use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\JWTProvider;
use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;

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

		$this->app['Tymon\JWTAuth\JWTAuth'] = function ($app)
		{
			return $app['tymon.jwt.auth'];
		};

		$this->app['Tymon\JWTAuth\JWTProvider'] = function ($app)
		{
			return $app['tymon.jwt.provider'];
		};

		$this->app['tymon.jwt.generate'] = $this->app->share(function($app)
        {
            return new JWTGenerateCommand($app['files']);
        });

        $this->commands('tymon.jwt.generate');
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->registerJWTProvider();
		$this->registerJWTAuth();
	}

	protected function registerJWTProvider()
	{
		$this->app['tymon.jwt.provider'] = $this->app->share(function ($app) {
			$secret = $app['config']->get('jwt::secret', 'changeme');
			$ttl = $app['config']->get('jwt::ttl', 120);
			$algo = $app['config']->get('jwt::algo', 'HS256');

			$provider = new JWTProvider($secret, $app['request']);

			return $provider->setTTL($ttl)->setAlgo($algo);
		});
	}

	protected function registerJWTAuth()
	{
		$this->app['tymon.jwt.auth'] = $this->app->share(function ($app) {
			$identifier = $app['config']->get('jwt::identifier', 'id');

			$auth = new JWTAuth( $app['tymon.jwt.provider'], $app['auth'] );

			return $auth->setIdentifier($identifier);
		});
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
			'Tymon\JWTAuth\JWTProvider',
			'Tymon\JWTAuth\JWTAuth'
		];
	}

}
