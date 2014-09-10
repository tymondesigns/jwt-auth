<?php namespace Tymon\JWTAuth;

use User;
use Tymon\JWTAuth\JWTProvider;
use Illuminate\Auth\AuthManager;

class JWTAuth {

	/**
	 * @var JWTProvider
	 */
	protected $provider;

	/**
	 * @var string
	 */
	protected $identifier;

	/**
	 * @var \Illuminate\Auth\AuthManager
	 */
	protected $auth;

	/**
	 * @param JWTProvider $provider
	 */
	public function __construct(JWTProvider $provider, AuthManager $auth, $identifier = 'id')
	{
		$this->provider = $provider;
		$this->identifier = $identifier;
		$this->auth = $auth;
	}

	/**
	 * Find a user using the user identifier in the subject claim
	 * 
	 * @param $token
	 * @return User
	 */
	public function toUser($token = null)
	{
		$payload = $this->provider->decode($token);

		return User::where($this->identifier, $payload['sub'])->first();
	}

	/**
	 * Generate a token using the user identifier as the subject claim
	 * 
	 * @param $user
	 * @return string
	 */
	public function fromUser(User $user)
	{
		return $this->provider->encode($user->{$this->identifier});
	}

	/**
	 * Attempt to authenticate the user and return the token
	 *  
	 * @param  array $credentials
	 * @return User
	 * @throws JWTAuthException
	 */
	public function attempt(array $credentials = [])
	{
		if ( $this->auth->once($credentials) )
		{
			return $this->fromUser( $this->auth->user() );
		}

		throw new JWTAuthException('Invalid credentials.');
	}

	/**
	 * Magically call the JWT provider
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
