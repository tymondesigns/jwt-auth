<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class Token {

	/**
	 * @var string
	 */
	protected $value;

	/**
	 * Create a new JSON Web Token
	 * 
	 * @param string $value
	 */
	public function __construct($value)
	{
		$this->value = $this->validateToken($value);
	}

	/**
	 * Validate the token
	 * 
	 * @param string $value
	 * @return string
	 * @throws Exceptions\JWTException
	 */
	protected function validateToken($value)
	{
		if ( count(explode('.', $value)) !== 3 )
		{
			throw new TokenInvalidException('Wrong number of segments');
		}

		return $value;
	}

	/**
	 * Get the token
	 * 
	 * @return string
	 */
	public function get()
	{
		return $this->value;
	}

	/**
	 * Get the token when casting to string
	 * 
	 * @return string
	 */
	public function __toString()
	{
		return $this->value;
	}

}
