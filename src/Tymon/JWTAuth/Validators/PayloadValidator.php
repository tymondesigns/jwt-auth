<?php namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\JWTException;

class PayloadValidator {

	/**
	 * @var array
	 */
	protected static $requiredClaims = ['iss', 'iat', 'exp', 'sub'];

	/**
	 * Run the validation on the payload array
	 * 
	 * @param  array  $payload
	 * @return void
	 */
	public static function check(array $payload)
	{
		self::validateStructure($payload);
		self::validateExpiry($payload);
	}

	/**
	 * Helper function to return a boolean
	 *
	 * @param  array  $payload 
	 * @return bool
	 */
	public static function isValid(array $payload)
	{
		try {
			self::check($payload);
		} catch (JWTException $e) {
			return false;
		}

		return true;
	}

	/**
	 * Ensure the payload contains the required claims
	 *
	 * @param  $payload
	 * @return bool
	 */
	protected static function validateStructure($payload)
	{
		if ( count( array_diff( self::$requiredClaims, array_keys($payload) ) ) !== 0 )
		{
			throw new TokenInvalidException('JWT payload does not contain the required claims');
		}

		return true;
	}

	/**
	 * Validate the issue and expiry date of the payload
	 *
	 * @param  $payload
	 * @return bool
	 */
	protected static function validateExpiry($payload)
	{
		if ( ! is_int($payload['exp']) )
		{
			throw new TokenInvalidException('Invalid Expiration (exp) provided');
		}

		if ( $payload['iat'] > time() || $payload['exp'] < time() )
		{
			throw new TokenExpiredException('JWT has expired');
		}

		return true;
	}
}