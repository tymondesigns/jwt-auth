<?php

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;

class JWT
{
  /**
   * @var \Tymon\JWTAuth\JWTManager
   */
  protected $manager;

  /**
   * @var \Illuminate\Http\Request
   */
  protected $request;

  /**
   * @var string
   */
  protected $identifier = 'id';

  /**
   * @var \Tymon\JWTAuth\Token
   */
  protected $token;

  /**
   * @param \Tymon\JWTAuth\JWTManager $manager
   * @param \Illuminate\Http\Request $request
   */
  public function __construct(JWTManager $manager, Request $request)
  {
    $this->manager = $manager;
    $this->request = $request;
  }

  /**
   * Refresh an expired token.
   *
   * @param mixed $token
   *
   * @return string
   */
  public function refresh($token = FALSE)
  {
    $this->requireToken($token);

    return $this->manager->refresh($this->token)->get();
  }

  /**
   * Invalidate a token (add it to the blacklist).
   *
   * @param mixed $token
   *
   * @return boolean
   */
  public function invalidate($token = FALSE)
  {
    $this->requireToken($token);

    return $this->manager->invalidate($this->token);
  }

  /**
   * Get the token.
   *
   * @return boolean|string
   */
  public function getToken()
  {
    if ( ! $this->token) {
      try {
        $this->parseToken();
      } catch (JWTException $e) {
        return FALSE;
      }
    }

    return $this->token;
  }

  /**
   * Get the raw Payload instance.
   *
   * @param mixed $token
   *
   * @return \Tymon\JWTAuth\Payload
   */
  public function getPayload($token = FALSE)
  {
    $this->requireToken($token);

    return $this->manager->decode($this->token);
  }

  /**
   * Parse the token from the request.
   *
   * @param string $query
   *
   * @return JWTAuth
   */
  public function parseToken($method = 'bearer', $header = 'authorization', $query = 'token')
  {
    if ( ! $token = $this->parseAuthHeader($header, $method)) {
      if ( ! $token = $this->request->query($query, FALSE)) {
        throw new JWTException('The token could not be parsed from the request', 400);
      }
    }

    return $this->setToken($token);
  }

  /**
   * Parse token from the authorization header.
   *
   * @param string $header
   * @param string $method
   *
   * @return false|string
   */
  protected function parseAuthHeader($header = 'authorization', $method = 'bearer')
  {
    $header = $this->request->headers->get($header);

    if ( ! starts_with(strtolower($header), $method)) {
      return FALSE;
    }

    return trim(str_ireplace($method, '', $header));
  }

  /**
   * Create a Payload instance.
   *
   * @param mixed $subject
   * @param array $customClaims
   *
   * @return \Tymon\JWTAuth\Payload
   */
  protected function makePayload($subject, array $customClaims = [])
  {
    return $this->manager->getPayloadFactory()->make(
      array_merge($customClaims, ['sub' => $subject])
    );
  }

  /**
   * Set the identifier.
   *
   * @param string $identifier
   * @return $this
   */
  public function setIdentifier($identifier)
  {
    $this->identifier = $identifier;

    return $this;
  }

  /**
   * Get the identifier.
   *
   * @return string
   */
  public function getIdentifier()
  {
    return $this->identifier;
  }

  /**
   * Set the token.
   *
   * @param string $token
   *
   * @return $this
   */
  public function setToken($token)
  {
    $this->token = new Token($token);

    return $this;
  }

  /**
   * Ensure that a token is available.
   *
   * @param mixed $token
   *
   * @return JWTAuth
   *
   * @throws \Tymon\JWTAuth\Exceptions\JWTException
   */
  protected function requireToken($token)
  {
    if ( ! $token = $token ?: $this->token) {
      throw new JWTException('A token is required', 400);
    }

    return $this->setToken($token);
  }

  /**
   * Set the request instance.
   *
   * @param Request $request
   */
  public function setRequest(Request $request)
  {
    $this->request = $request;

    return $this;
  }

  /**
   * Get the JWTManager instance.
   *
   * @return \Tymon\JWTAuth\JWTManager
   */
  public function manager()
  {
    return $this->manager;
  }

  /**
   * Magically call the JWT Manager.
   *
   * @param string $method
   * @param array $parameters
   *
   * @return mixed
   *
   * @throws \BadMethodCallException
   */
  public function __call($method, $parameters)
  {
    if (method_exists($this->manager, $method)) {
      return call_user_func_array([$this->manager, $method], $parameters);
    }

    throw new \BadMethodCallException("Method [$method] does not exist.");
  }
}
