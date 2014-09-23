<?php namespace Tymon\JWTAuth\Drivers;

use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Payload;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Exception;

abstract class AbstractDriver {

	/**
	 * @var string
	 */
	protected $secret;

	/**
	 * @var \Illuminate\Http\Request
	 */
	protected $request;

	/**
	 * @var string
	 */
	protected $token;

	/**
	 * @var array
	 */
	protected $payload;

	/**
	 * @var int
	 */
	protected $ttl = 120;

	/**
	 * @var string
	 */
	protected $algo = 'HS256';

	/**
	 * @param $secret
	 * @param Request $request
	 */
	public function __construct($secret, Request $request)
	{
		$this->secret = $secret;
		$this->request = $request;
	}

	/**
	 * Build the payload for the token
	 * 
	 * @param $subject
	 * @param $subject
	 * @return array
	 */
	protected function buildPayload($subject, array $customClaims = [])
	{
		$payload = array_merge($customClaims, [
			'iss' => $this->request->url(),
			'sub' => $subject,
			'iat' => time(),
			'exp' => time() + ($this->ttl * 60)
		]);

		return $this->createPayload($payload)->get();
	}

	/**
	 * Create a new JWT value object
	 * 
	 * @param string $token
	 * @return Token
	 */
	public function createToken($token)
	{
		$this->token = new Token($token);

		return $this->token;
	}

	/**
	 * Create a new JWTPayload value object
	 * 
	 * @param $payload
	 * @return Payload
	 */
	public function createPayload($payload)
	{
		$this->payload = new Payload($payload);

		return $this->payload;
	}

		/**
	 * Get the JWT Payload
	 * 
	 * @return JWTPayload
	 */
	public function getPayload()
	{
		return $this->payload;
	}

	/**
	 * Get the JWT
	 * 
	 * @return string
	 */
	public function getToken()
	{
		return $this->token;
	}

		/**
	 * Set the ttl of the token
	 * 
	 * @param int $ttl in minutes
	 */
	public function setTTL($ttl)
	{
		$this->ttl = $ttl;

		return $this;
	}

	/**
	 * Set the algorithm of the token
	 * 
	 * @param string $algo
	 */
	public function setAlgo($algo)
	{
		$this->algo = $algo;

		return $this;
	}

	/**
	 * Helper method to return the subject claim
	 * 
	 * @param  string $token
	 * @return mixed
	 */
	public function getSubject($token)
	{
		return $this->decode($token)->get('sub');
	}

}