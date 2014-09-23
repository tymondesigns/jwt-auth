<?php namespace Tymon\JWTAuth\Drivers;

use Tymon\JWTAuth\Drivers\AbstractDriver;
use Tymon\JWTAuth\Drivers\DriverInterface;
use Tymon\JWTAuth\Exceptions\JWTException;
use JWT as Firebase;

class Firebase extends AbstractDriver implements DriverInterface {

	/**
	 * Create a JSON Web Token
	 * 
	 * @param mixed $subject
	 * @param array $customClaims
	 * @return Token
	 * @throws Exceptions\JWTException
	 */
	public function encode($subject, array $customClaims = [])
	{
		if ( is_null($subject) ) throw new JWTException('A subject is required');

		try
		{
			$token = Firebase::encode( $this->buildPayload($subject, $customClaims), $this->secret, $this->algo );
			$this->createToken($token);
		}
		catch (Exception $e)
		{
			throw new JWTException( 'Could not create token: ' . $e->getMessage() );
		}

		return $this->token;
	}

	/**
	 * Decode a JSON Web Token
	 * 
	 * @param string $token
	 * @return Payload
	 * @throws Exceptions\JWTException
	 */
	public function decode($token = null)
	{
		if ( is_null($token) ) throw new JWTException('A token is required');

		$this->createToken($token);

		try
		{
			$payload = (array) Firebase::decode( $this->token, $this->secret );
			$this->createPayload($payload);
		}
		catch (Exception $e)
		{
			throw new JWTException( 'Could not decode token: ' . $e->getMessage() );
		}

		return $this->payload;
	}

}