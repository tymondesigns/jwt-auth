<?php namespace Tymon\JWTAuth;

use JWT as JWTBuilder;
use Tymon\JWTAuth\JWT;
use Tymon\JWTAuth\JWTPayload;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;

class JWTDriver {

	/**
	 * @var
	 */
	protected $secret;

	/**
	 * @var \Illuminate\Http\Request
	 */
	protected $request;

	/**
	 * @var
	 */
	protected $token;

	/**
	 * @var
	 */
	protected $payload;

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
	 * @param null $subject
	 * @param array $customClaims
	 * @return mixed
	 * @throws Exceptions\JWTException
	 */
	public function encode($subject = null, array $customClaims = [])
	{
		if ( is_null($subject) ) throw new JWTException('A subject is required');

		try
		{
			$token = JWTBuilder::encode( $this->buildPayload($subject, $customClaims), $this->secret );
			$this->createJWT($token);
		}
		catch (Exception $e)
		{
			throw new JWTException( $e->getMessage() );
		}

		return $this->token;
	}

	/**
	 * @param null $token
	 * @return mixed
	 * @throws TokenException
	 * @throws Exceptions\JWTException
	 */
	public function decode($token = null)
	{
		if ( is_null($token) ) throw new TokenException('A token is required');

		$this->createJWT($token);

		try
		{
			$payload = JWTBuilder::decode( $token, $this->secret );
			$this->createPayload($payload);
		}
		catch (Exception $e)
		{
			throw new JWTException( $e->getMessage() );
		}

		return $this->payload;
	}

	/**
	 * @param $token
	 * @return JWT
	 */
	public function createJWT($token)
	{
		$this->token = new JWT($token);

		return $this->token;
	}

	/**
	 * @param $payload
	 * @return JWTPayload
	 */
	public function createPayload($payload)
	{
		$this->payload = new JWTPayload($payload);

		return $this->payload;
	}

	/**
	 * Create a new JWTPayload value object
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
			'exp' => time() + (60 * 60),
			'jti' => '123'
		], $customClaims);

		$this->createPayload($payload);

		return $this->payload->get();
	}

}
