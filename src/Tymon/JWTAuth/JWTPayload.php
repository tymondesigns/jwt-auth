<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Exceptions\JWTPayloadException;

class JWTPayload {

	/**
	 * @var array
	 */
	protected $value;

	/**
	 * @var array
	 */
	protected $requiredClaims = ['iss', 'iat', 'exp', 'sub', 'jti'];

	/**
	 * Create a new JWT payload
	 *
	 * @param array $value
	 */
	public function __construct(array $value)
	{
		$this->value = $this->validatePayload($value);
	}

	/**
	 * Perform some validation checks on the payload
	 * 
	 * @param $value
	 */
	protected function validatePayload($value)
	{
		$this->validateStructure($value);

		return $value;
	}

	/**
	 * Validate the structure of the payload
	 * 
	 * @param  array $value
	 * @return bool
	 * @throws \Tymon\JWTAuth\Exceptions\JWTPayloadException
	 */
	protected function validateStructure($value)
	{
		if ( count( array_diff( $this->requiredClaims, array_keys($value) ) ) !== 0 )
		{
			throw new JWTPayloadException('JWT payload does not contain the required claims');
		}

		return true;
	}

	/**
	 * Get the payload
	 * 
	 * @return array
	 */
	public function get()
	{
		return $this->value;
	}

}