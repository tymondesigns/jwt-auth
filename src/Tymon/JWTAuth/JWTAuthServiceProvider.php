<?php namespace Tymon\JWTAuth;

use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\JWTProvider;
use Tymon\JWTAuth\JWTAuth;

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

		$this->app['Tymon\JWTAuth\JWTAuth'] = function ($app) {
			return $app['tymon.jwt.auth'];
		};

		$this->app['Tymon\JWTAuth\JWTProvider'] = function ($app) {
			return $app['tymon.jwt.provider'];
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
		$this->registerJWTAuth();
	}

	protected function registerJWTProvider()
	{
		$this->app['tymon.jwt.provider'] = $this->app->share(function ($app) {
			$secret = $app['config']->get('jwt::secret');
			$ttl = $app['config']->get('jwt::ttl');

			$provider = new JWTProvider($secret, $app['request']);

			return $provider->setTTl($ttl);
		});
	}

	protected function registerJWTAuth()
	{
		$this->app['tymon.jwt.auth'] = $this->app->share(function ($app) {
			$identifier = $app['config']->get('jwt::identifier');

			return new JWTAuth( $app['tymon.jwt.provider'], $identifier );
		});
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return [
			'tymon.jwt.provider',
			'tymon.jwt.auth',
			'Tymon\JWTAuth\JWTProvider',
			'Tymon\JWTAuth\JWTAuth'
		];
	}

}
