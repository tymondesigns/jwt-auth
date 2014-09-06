<?php namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Exceptions\JWTException;

class JWT {

	/**
	 * @var string
	 */
	protected $value;

	/**
	 * @param $value
	 */
	public function __construct($value)
	{
		$this->value = $this->validateJWT($value);
	}

	/**
	 * @param $value
	 * @return string
	 * @throws Exceptions\JWTException
	 */
	protected function validateJWT($value)
	{
		if(! is_string($value))
		{
			throw new JWTException('JWT must be a string');
		}

		return $value;
	}

	/**
	 * @return string
	 */
	public function get()
	{
		return $this->value;
	}

	/**
	 * @return string
	 */
	public function __toString()
	{
		return $this->value;
	}

}
