<?php namespace Tymon\JWTAuth\Providers;

use Tymon\JWTAuth\Providers\AbstractProvider;
use Tymon\JWTAuth\Providers\ProviderInterface;
use Tymon\JWTAuth\Exceptions\JWTException;
use JWT as Firebase;
use Exception;

class FirebaseProvider extends AbstractProvider implements ProviderInterface {

	/**
	 * Create a JSON Web Token
	 * 
	 * @param mixed $subject
	 * @param array $customClaims
	 * @return \Tymon\JWTAuth\Token
	 * @throws \Tymon\JWTAuth\Exceptions\JWTException
	 */
	public function encode($subject = false, array $customClaims = [])
	{
		if ( ! $subject ) throw new JWTException('A subject is required');

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
	 * @return \Tymon\JWTAuth\Payload
	 * @throws \Tymon\JWTAuth\Exceptions\JWTException
	 */
	public function decode($token = false)
	{
		if ( ! $token ) throw new JWTException('A token is required');

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