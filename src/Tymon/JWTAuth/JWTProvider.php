<?php namespace Tymon\JWTAuth;

use JWT as JWTDriver;
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Payload;
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
	 * Create a JSON Web Token
	 * 
	 * @param mixed $subject
	 * @param array $customClaims
	 * @return string
	 * @throws Exceptions\JWTException
	 */
	public function encode($subject = null, array $customClaims = [])
	{
		if ( is_null($subject) ) throw new JWTException('A subject is required');

		try
		{
			$token = JWTDriver::encode( $this->buildPayload($subject, $customClaims), $this->secret, $this->algo );
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
	 * @return mixed
	 * @throws TokenException
	 * @throws Exceptions\JWTException
	 */
	public function decode($token = null)
	{
		if ( is_null($token) ) throw new JWTException('A token is required');

		$this->createToken($token);

		try
		{
			$payload = (array) JWTDriver::decode( $this->token, $this->secret );
			$this->createPayload($payload);
		}
		catch (Exception $e)
		{
			throw new JWTException( 'Could not decode token: ' . $e->getMessage() );
		}

		return $this->payload;
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
	 * Helper method to return the subject claim
	 * 
	 * @param  string $token
	 * @return mixed
	 */
	public function getSubject($token)
	{
		return $this->decode($token)->get('sub');
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

}
