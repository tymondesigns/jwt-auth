<?php namespace Tymon\JWTAuth;

use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\JWTAuth;

class JWTAuthServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 *
	 */
	public function boot()
	{
		$this->package('tymon/jwt-auth', 'jwt');
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->app->bind('Tymon\JWTAuth\JWTAuth', function($app)
		{
			$secret = $app['config']->get('jwt::secret');
			$identifier = $app['config']->get('jwt::identifier');
			
			return new JWTAuth( $secret, $identifier, $app['request'], $app['config'], $app['crypt'] );
		});
	}

	

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array('Tymon\JWTAuth\JWTAuth');
	}

}
