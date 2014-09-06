<?php namespace Tymon\JWTAuth;

use JWT;
use Illuminate\Http\Request;
use Illuminate\Config\Repository;
use Illuminate\Encryption\Encrypter;
use Tymon\JWTAuth\Exceptions\TokenException;
use User;

class JWTAuth {

	/**
	 * @var string
	 */
	protected $driver;

	/**
	 * @param string $driver
	 */
	public function __construct(JWTDriver $driver)
	{
		$this->driver = $driver;
	}


	/**
	 * Find a user using the user identifier in the subject claim
	 * 
	 * @param $token
	 * @return mixed
	 */
	public function toUser($token = null)
	{
		$this->payload = $this->decode($token);

		return User::where($this->identifier, $this->payload['sub']);
	}

	/**
	 * Generate a token using the user identifier as the subject claim
	 * 
	 * @param $user
	 * @return string
	 */
	public function fromUser(User $user)
	{
		return $this->encode($user->{$this->identifier});
	}

	protected function checkExp()
	{
		if ( isset($this->payload['exp']) )
		{
			if (! ctype_digit($this->payload['exp']))
			{
				throw new TokenException('Expiration (exp) must be a unix timestamp');
			}
			
			return true;
		}
	
		throw new TokenException('Invalid Expiration (exp) provided');
	}

	/**
	 * Determine whether the token has expired
	 *
	 * @return bool
	 */
	protected function hasExpired()
	{
		return $this->payload['iat'] > time() && $this->payload['exp'] < time();
	}

	/**
	 * Check the jti 
	 *
	 * @return bool
	 */
	protected function verifyId()
	{
		$value = explode( '|', $this->encryptor->decrypt($this->payload['jti']) );

		return $this->payload['sub'] === $value[0] && $this->payload['iat'] === $value[1];
	}

}
