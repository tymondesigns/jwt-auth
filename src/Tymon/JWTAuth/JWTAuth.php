<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\ProviderInterface;
use Tymon\JWTAuth\Exceptions\JWTAuthException;
use Illuminate\Auth\AuthManager;
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
	 * @param $token
	 * @return User
	 */
	public function toUser($token)
	{
		$this->driver->decode($token);

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
	public function fromUser(User $user)
	{
		return $this->provider->encode($user->{$this->identifier})->get();
	}

	/**
	 * Attempt to authenticate the user and return the token
	 *  
	 * @param  array $credentials
	 * @return string
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
	 * @return User        
	 */
	public function login($token)
	{
		if (! $token) throw new JWTAuthException('A token is required');

		$id = $this->provider->getSubject($token);

		if (! $user = $this->auth->loginUsingId($id) )
		{
			throw new JWTAuthException('User not found.');
		}

		return $user;
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
