<?php namespace Tymon\JWTAuth;

use JWT as JWTDriver;
use Tymon\JWTAuth\JWT;
use Tymon\JWTAuth\JWTPayload;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Exception;

class JWTProvider {

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
	 * @param $secret
	 * @param Request $request
	 */
	public function __construct($secret, Request $request)
	{
		$this->secret = $secret;
		$this->request = $request;
	}

	/**
	 * Create a JSON Web Token
	 * 
	 * @param mixed $subject
	 * @param array $customClaims
	 * @return mixed
	 * @throws Exceptions\JWTException
	 */
	public function encode($subject = null, array $customClaims = [])
	{
		if ( is_null($subject) ) throw new JWTException('A subject is required');

		try
		{
			$token = JWTDriver::encode( $this->buildPayload($subject, $customClaims), $this->secret );
			$this->createJWT($token);
		}
		catch (Exception $e)
		{
			throw new JWTException( $e->getMessage() );
		}

		return $this->token;
	}

	/**
	 * Decode a JSON Web Token
	 * 
	 * @param string $token
	 * @return mixed
	 * @throws TokenException
	 * @throws Exceptions\JWTException
	 */
	public function decode($token = null)
	{
		if ( is_null($token) ) throw new JWTException('A token is required');

		$this->createJWT($token);

		try
		{
			$payload = JWTDriver::decode( $this->token->get(), $this->secret );
			$this->createPayload($payload);
		}
		catch (Exception $e)
		{
			throw new JWTException( $e->getMessage() );
		}

		return $this->payload;
	}

	/**
	 * Create a new JWT value object
	 * 
	 * @param $token
	 * @return JWT
	 */
	public function createJWT($token)
	{
		$this->token = new JWT($token);

		return $this->token;
	}

	/**
	 * Create a new JWTPayload value object
	 * 
	 * @param $payload
	 * @return JWTPayload
	 */
	public function createPayload($payload)
	{
		$this->payload = new JWTPayload($payload);

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
	 * @return JWT
	 */
	public function getToken()
	{
		return $this->token;
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
		$payload = array_merge([
			'iss' => $this->request->url(),
			'sub' => $subject,
			'iat' => time(),
			'exp' => time() + ($this->ttl * 60)
		], $customClaims);

		return $this->createPayload($payload)->get();
	}

	protected function setTtl($ttl)
	{
		$this->ttl = $ttl;

		return $this;
	}

}
