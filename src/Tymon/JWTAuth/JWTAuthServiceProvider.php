<?php namespace Tymon\JWTAuth;

use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\JWTAuth;
use Tymon\JWTAuth\Commands\JWTGenerateCommand;
use Tymon\JWTAuth\JWTAuthFilter;

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

		$this->app['Tymon\JWTAuth\Providers\ProviderInterface'] = function ($app)
		{
			return $app['tymon.jwt.provider'];
		};

		$this->app['tymon.jwt.generate'] = $this->app->share(function($app)
        {
            return new JWTGenerateCommand($app['files']);
        });

        $this->commands('tymon.jwt.generate');

        $this->app['router']->filter('jwt-auth', 'tymon.jwt.filter');
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
		$this->registerJWTAuthFilter();
	}

	protected function registerJWTProvider()
	{
		$this->app['tymon.jwt.provider'] = $this->app->share(function ($app) {

			$secret = $app['config']->get('jwt::secret', 'changeme');
			$ttl = $app['config']->get('jwt::ttl', 120);
			$algo = $app['config']->get('jwt::algo', 'HS256');
			$provider = $app['config']->get('jwt::provider', 'Tymon\JWTAuth\Providers\FirebaseProvider');

			$instance = $app->make($provider , [ $secret, $app['request'] ] );

			return $instance->setTTL($ttl)->setAlgo($algo);
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

	protected function registerJWTAuthFilter()
	{
		$this->app['tymon.jwt.filter'] = $this->app->share(function ($app) {
			return new JWTAuthFilter($app['events']);
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
			'Tymon\JWTAuth\Providers\ProviderInterface',
			'Tymon\JWTAuth\JWTAuth'
		];
	}

}
