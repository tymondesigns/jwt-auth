<?php namespace Tymon\JWTAuth;

use JWT;
use Illuminate\Http\Request;
use Illuminate\Config\Repository;
use Tymon\JWTAuth\Exceptions\TokenException;
use User;

class JWTAuth {

	/**
	 * @var string
	 */
	protected $secret;

	/**
	 * @var string
	 */
	protected $identifier;

	/**
	 * @var \Illuminate\Http\Request
	 */
	protected $request;

	/**
	 * @var \Illuminate\Config\Repository
	 */
	protected $config;

	/**
	 * @var array
	 */
	protected $payload;

	/**
	 * @param string $secret
	 * @param string $identifier
	 * @param Request $request
	 * @param Repository $config
	 */
	public function __construct($secret = 'changeme', $identifier = 'id', Request $request, Repository $config)
	{
		$this->secret = $secret;
		$this->identifier = $identifier;
		$this->request = $request;
		$this->config = $config;
	}


	/**
	 * Create the token using the subject
	 * 
	 * @param null $subject
	 * @return string
	 * @throws Exceptions\TokenException
	 */
	public function encode($subject = null)
	{
		if ( is_null($subject) ) throw new TokenException('A subject is required');

		try
		{
			return JWT::encode(
				$this->buildPayload($subject),
				$this->secret,
				$this->config->get('jwt::algo', 'HS256')
			);
		}
		catch (Exception $e)
		{
			throw new TokenException( $e->getMessage() );
		}
	}

	/**
	 * @param null $token
	 * @return object
	 */
	public function decode($token = null)
	{
		try
		{
			$this->payload = (array) JWT::decode($token, $this->secret);
		}
		catch (Exception $e)
		{
			throw new TokenException( $e->getMessage() );
		}

		if (! $this->verifyPayload())
		{
			throw new TokenException('Token Not Valid');
		}

		return $this->payload;
	}

	/**
	 * Check to see if the token is valid
	 * 
	 * @param $token
	 * @return bool
	 */
	public function check($token)
	{
		try
		{
			$this->payload = JWT::decode($token, $this->secret);
		}
		catch(TokenException $e)
		{
			return false;
		}

		return $this->verifyPayload();
	}

	/**
	 * Find a user using the user identifier in the subject claim
	 * 
	 * @param $token
	 * @return mixed
	 */
	public function toUser($token)
	{
		try
		{
			$this->payload = $this->decode($token);
		}
		catch(TokenException $e)
		{
			throw $e;
		}

		return User::where($this->identifier, $this->payload['sub']);
	}

	/**
	 * Generate a token using the user identifier as the subject claim
	 * 
	 * @param $user
	 * @return string
	 */
	public function fromUser($user)
	{
		return $this->encode($user->{$this->identifier});
	}

	/**
	 * Build the claims array for the token
	 * 
	 * @param $subject
	 * @return array
	 */
	protected function buildPayload($subject)
	{
		$this->payload = [
			'iss' => $this->request->url(),
			'sub' => $subject,
			'iat' => time(),
			'exp' => time() + ($this->config->get('jwt::ttl', 60) * 60),
			'jti' => base64_encode($subject . '|' . time())
		];

		return $this->payload;
	}

	/**
	 * Verify that the token has not expired and contains the correct data
	 * 
	 * @param $payload
	 * @return bool
	 */
	protected function verifyPayload()
	{
		if ( $this->hasExpired() || !$this->verifyId() ) return false;

		return true;
	}


	/**
	 * Determine whether the token has expired
	 *
	 * @return bool
	 */
	protected function hasExpired()
	{
		return $this->payload['iat'] > time() || $this->payload['exp'] < time();
	}

	protected function verifyId()
	{
		$value = explode( '|', base64_decode($this->payload['jti']) );

		return $value['sub'] === $value[0] && $value['iat'] === $value[1];
	}

}