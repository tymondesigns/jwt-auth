<?php namespace Tymon\JWTAuth;

use User;
use Tymon\JWTAuth\JWTProvider;

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
	 * @param JWTProvider $provider
	 */
	public function __construct(JWTProvider $provider, $identifier = 'id')
	{
		$this->provider = $provider;
		$this->identifier = $identifier;
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

}
