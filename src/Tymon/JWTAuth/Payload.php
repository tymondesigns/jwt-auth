<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Exceptions\PayloadException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use ArrayAccess;

class Payload implements ArrayAccess {

	/**
	 * @var array
	 */
	protected $value;

	/**
	 * @var array
	 */
	protected $requiredClaims = ['iss', 'iat', 'exp', 'sub'];

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
		$this->validateExpiry($value);

		return $value;
	}

	/**
	 * Validate the structure of the payload
	 * 
	 * @param  array $value
	 * @return bool
	 * @throws Exceptions\PayloadException
	 */
	protected function validateStructure($value)
	{
		if ( count( array_diff( $this->requiredClaims, array_keys($value) ) ) !== 0 )
		{
			throw new TokenInvalidException('JWT payload does not contain the required claims');
		}

		return true;
	}

	/**
	 * Validate the expiry date of the payload
	 * 
	 * @param  array $value
	 * @return bool
	 * @throws Exceptions\PayloadException
	 */
	protected function validateExpiry($value)
	{
		if ( ! is_int($value['exp']) )
		{
			throw new TokenInvalidException('Invalid Expiration (exp) provided');
		}

		if ( $value['iat'] > time() || $value['exp'] < time() )
		{
			throw new TokenExpiredException('JWT has expired');
		}

		return true;
	}

	/**
	 * Get the payload
	 * 
	 * @param string $property
	 * @return array
	 */
	public function get($property = null)
	{
		if ( ! is_null($property) )
		{
			return $this->value[$property];
		}
		
		return $this->value;
	}

	/**
	 * Get the payload as a string
	 * 
	 * @return string
	 */
	public function __toString()
	{
		return json_encode($this->value);
	}

	/**
	 * Determine if an item exists at an offset.
	 *
	 * @param  mixed  $key
	 * @return bool
	 */
	public function offsetExists($key)
	{
		return array_key_exists($key, $this->value);
	}

	/**
	 * Get an item at a given offset.
	 *
	 * @param  mixed  $key
	 * @return mixed
	 */
	public function offsetGet($key)
	{
		return $this->value[$key];
	}

	/**
	 * Don't allow changing the payload as it should be immutable
	 *
	 * @param  mixed  $key
	 * @param  mixed  $value
	 * @return void
	 */
	public function offsetSet($key, $value)
	{
		throw new PayloadException('You cannot change the payload');
	}

	/**
	 * Don't allow changing the payload as it should be immutable
	 *
	 * @param  string  $key
	 * @return void
	 */
	public function offsetUnset($key)
	{
		throw new PayloadException('You cannot change the payload');
	}

}