<?php

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Auth\AuthInterface;
use Tymon\JWTAuth\Exceptions\JWTAuthException;
use Tymon\JWTAuth\JWT\JWTInterface;
use Tymon\JWTAuth\User\UserInterface;

class JWTAuth
{

    /**
     * @var \Tymon\JWTAuth\User\UserInterface
     */
    protected $user;

    /**
     * @var \Tymon\JWTAuth\JWT\JWTInterface
     */
    protected $jwt;

    /**
     * @var \Tymon\JWTAuth\Auth\AuthInterface
     */
    protected $auth;

    /**
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * @var string
     */
    protected $identifier = 'id';

    /**
     * @var string
     */
    protected $token;

    /**
     * @param \Tymon\JWTAuth\User\UserInterface  $user
     * @param \Tymon\JWTAuth\JWT\JWTInterface  $jwt
     * @param \Tymon\JWTAuth\Auth\AuthInterface  $auth
     * @param \Illuminate\Http\Request  $request
     */
    public function __construct(UserInterface $user, JWTInterface $jwt, AuthInterface $auth, Request $request)
    {
        $this->user = $user;
        $this->jwt = $jwt;
        $this->auth = $auth;
        $this->request = $request;
    }

    /**
     * Find a user using the user identifier in the subject claim
     *
     * @param  string  $token
     * @return mixed
     */
    public function toUser($token = false)
    {
        $this->requireToken($token);

        $this->jwt->decode($this->token);

        if (! $user = $this->user->getBy($this->identifier, $this->jwt->getSubject())) {
            return false;
        }

        return $user;
    }

    /**
     * Generate a token using the user identifier as the subject claim
     *
     * @param  mixed  $user
     * @param  array  $customClaims
     * @return string
     */
    public function fromUser($user, array $customClaims = [])
    {
        return $this->jwt->encode($user->{$this->identifier}, $customClaims)->get();
    }

    /**
     * Attempt to authenticate the user and return the token
     *
     * @param  array  $credentials
     * @param  array  $customClaims
     * @return false|string
     */
    public function attempt(array $credentials = [], array $customClaims = [])
    {
        if (! $this->auth->check($credentials)) {
            return false;
        }

        return $this->fromUser($this->auth->user(), $customClaims);
    }

    /**
     * Log the user in via the token
     *
     * @param  mixed  $token
     * @return mixed
     */
    public function login($token = false)
    {
        $this->requireToken($token);

        $id = $this->jwt->getSubject($this->token);

        if (! $user = $this->auth->checkUsingId($id)) {
            return false;
        }

        return $user;
    }

    /**
     * Get the token
     *
     * @return false|string
     */
    public function getToken()
    {
        if (! $this->token) {
            if (! $this->parseToken()) {
                return false;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request
     *
     * @param  string  $query
     * @return mixed
     */
    public function parseToken($query = 'token')
    {
        if ( ! $token = $this->parseAuthHeader() )
        {
            if ( ! $token = $this->request->query($query, false) )
            {
                return false;
            }
        }

        return $this->setToken($token);
    }

    /**
     * Parse token from the authorization header
     *
     * @return false|string
     */
    protected function parseAuthHeader($method = 'bearer')
    {
        $header = $this->request->headers->get('authorization');

        if (! starts_with(strtolower($header), $method)) {
            return false;
        }

        return trim(str_ireplace($method, '', $header));
    }

    /**
     * Set the identifier
     *
     * @param string $identifier
     */
    public function setIdentifier($identifier)
    {
        $this->identifier = $identifier;

        return $this;
    }

    /**
     * Get the identifier
     *
     * @return string
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * Set the token
     *
     * @param string  $token
     */
    public function setToken($token)
    {
        $this->token = $token;

        return $this;
    }

    /**
     * Ensure that a token is available
     *
     * @param  mixed  $token
     * @return void
     * @throws \Tymon\JWTAuth\Exceptions\JWTAuthException
     */
    protected function requireToken($token)
    {
        if ($token) {
            $this->setToken($token);
        } else {
            if (! $this->token) {
                throw new JWTAuthException('A token is required');
            }
        }
    }

    /**
     * Magically call the JWT provider
     *
     * @param  string  $method
     * @param  array   $parameters
     * @return mixed
     * @throws \BadMethodCallException
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        throw new \BadMethodCallException('Method [$method] does not exist.');
    }
}
