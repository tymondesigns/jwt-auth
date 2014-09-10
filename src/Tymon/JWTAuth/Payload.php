<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Exceptions\JWTPayloadException;
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
	 * @throws Exceptions\JWTPayloadException
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
	 * Validate the expiry date of the payload
	 * 
	 * @param  array $value
	 * @return bool
	 * @throws Exceptions\JWTPayloadException
	 */
	protected function validateExpiry($value)
	{
		if ( ! is_int($value['exp']) )
		{
			throw new JWTPayloadException('Invalid Expiration (exp) provided');
		}

		if ( $value['iat'] > time() || $value['exp'] < time() )
		{
			throw new JWTPayloadException('JWT has expired');
		}

		return true;
	}

	/**
	 * Get the payload
	 * 
	 * @return array
	 */
	public function get($property = null)
	{
		if (! is_null($property) )
		{
			return $this->value[$property];
		}
		
		return $this->value;
	}

	/**
	 * Get the payload as a string
	 * 
	 * @return array
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
	 * Set the item at a given offset.
	 *
	 * @param  mixed  $key
	 * @param  mixed  $value
	 * @return void
	 */
	public function offsetSet($key, $value)
	{
		if (is_null($key))
		{
			$this->value[] = $value;
		}
		else
		{
			$this->value[$key] = $value;
		}
	}

	/**
	 * Unset the item at a given offset.
	 *
	 * @param  string  $key
	 * @return void
	 */
	public function offsetUnset($key)
	{
		unset($this->value[$key]);
	}

}