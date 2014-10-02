<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\ProviderInterface;
use Tymon\JWTAuth\Exceptions\JWTAuthException;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use User;

class JWTAuth {

	/**
	 * @var \Tymon\JWTAuth\Providers\ProviderInterface
	 */
	protected $provider;

	/**
	 * @var \Illuminate\Auth\AuthManager
	 */
	protected $auth;

	/**
	 * @var string
	 */
	protected $identifier = 'id';

	/**
	 * @var string
	 */
	protected $token;

	/**
	 * @param \Tymon\JWTAuth\Providers\ProviderInterface $provider
	 */
	public function __construct(ProviderInterface $provider, AuthManager $auth)
	{
		$this->provider = $provider;
		$this->auth = $auth;
	}

	/**
	 * Find a user using the user identifier in the subject claim
	 * 
	 * @param  string $token
	 * @return mixed
	 */
	public function toUser($token = false)
	{
		$this->requireToken();

		$this->provider->decode($this->token);

		if ( ! $user = User::where( $this->identifier, $this->provider->getSubject() )->first() )
		{
			return false;
		}

		return $user;
	}

	/**
	 * Generate a token using the user identifier as the subject claim
	 * 
	 * @param $user
	 * @return string
	 */
	public function fromUser($user)
	{
		return $this->provider->encode($user->{$this->identifier})->get();
	}

	/**
	 * Attempt to authenticate the user and return the token
	 *  
	 * @param  array $credentials
	 * @return mixed
	 * @throws \Tymon\JWTAuth\Exceptions\JWTAuthException
	 */
	public function attempt(array $credentials = [])
	{
		if (! $this->auth->once($credentials) )
		{
			return false;
		}

		return $this->fromUser( $this->auth->user() );
	}

	/**
	 * Log the user in via the token
	 * 
	 * @param  string $token 
	 * @return mixed        
	 */
	public function login($token = false)
	{
		$this->requireToken();

		$id = $this->provider->getSubject($this->token);

		if (! $user = $this->auth->loginUsingId($id) )
		{
			return false;
		}

		return $user;
	}

	/**
	 * Get the token from the request
	 *
	 * @param  string $query
	 * @return mixed
	 */
	public function getToken($query = 'token')
	{
		$request = app('request');

		if ( ! $token = $this->parseAuthHeader($request) )
		{
			if ( ! $token = $request->query($query, false) )
			{
				return false;
			}
		}

		$this->setToken($token);

		return $token;
	}

	/**
	 * Parse token from the authorization header
	 *
	 * @param  \Illuminate\Http\Request $request
	 * @return mixed
	 */
	protected function parseAuthHeader(Request $request, $method = 'bearer')
	{
		$header = $request->headers->get('authorization');

		if ( ! starts_with( strtolower($header), $method ) ) {
			return false;
		}

		return trim( str_ireplace( $method, '', $header ) );
	}

	/**
	 * Get the JWT provider
	 * 
	 * @return \Tymon\JWTAuth\Providers\ProviderInterface
	 */
	public function getProvider()
	{
		return $this->provider;
	}

	/**
	 * Set the identifier
	 * 
	 * @param string $identifier
	 */
	public function setIdentifier($identifier)
	{
		$this->identifier = $identifier;

		return $this;
	}

	/**
	 * Set the token 
	 * 
	 * @param mixed $token
	 */
	public function setToken($token)
	{
		$this->token = $token;

		return $this;
	}

	/**
	 * Ensure that a token is available
	 * 
	 * @param  mixed $token 
	 * @return void
	 */
	protected function requireToken($token)
	{
		if ($token)
		{
			$this->setToken($token);
		}
		else if (! $this->token)
		{
			throw new JWTAuthException('A token is required');
		}
	}

	/**
	 * Magically call the JWT driver
	 * 
	 * @param  string $method
	 * @param  array  $parameters
	 * @return mixed           
	 * @throws \BadMethodCallException
	 */
	public function __call($method, $parameters)
	{
		if ( method_exists($this->provider, $method) )
		{
			return call_user_func_array([$this->provider, $method], $parameters);
		}

		throw new \BadMethodCallException('Method [$method] does not exist.');
	}

}
