<?php

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Auth\AuthInterface;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\JWT\JWTInterface;
use Tymon\JWTAuth\User\UserInterface;
use Tymon\JWTAuth\Token;

class JWTAuth
{

    /**
     * @var \Tymon\JWTAuth\User\UserInterface
     */
    protected $user;

    /**
     * @var \Tymon\JWTAuth\JWTManager
     */
    protected $manager;

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
     * @param \Tymon\JWTAuth\JWTManager  $manager
     * @param \Tymon\JWTAuth\Auth\AuthInterface  $auth
     * @param \Illuminate\Http\Request  $request
     */
    public function __construct(UserInterface $user, JWTManager $manager, AuthInterface $auth, Request $request)
    {
        $this->user = $user;
        $this->manager = $manager;
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

        $payload = $this->manager->decode($this->token);

        if (! $user = $this->user->getBy($this->identifier, $payload->get('sub'))) {
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
        $payload = $this->makePayload($user->{$this->identifier}, $customClaims);

        return $this->manager->encode($payload)->get();
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
     * Authenticate a user via a token
     *
     * @param  mixed  $token
     * @return mixed
     */
    public function authenticate($token = false)
    {
        $this->requireToken($token);

        $id = $this->manager->decode($this->token)->get('sub');

        if (! $this->auth->checkUsingId($id)) {
            return false;
        }

        return $this->auth->user();
    }

    /**
     * Refresh an expired token
     *
     * @param  mixed  $token
     * @return string
     */
    public function refresh($token = false)
    {
        $this->requireToken($token);

        return $this->manager->refresh($this->token)->get();
    }

    /**
     * Invalidate a token (add it to the blacklist)
     *
     * @param  mixed  $token
     * @return boolean
     */
    public function invalidate($token = false)
    {
        $this->requireToken($token);

        return $this->manager->invalidate($this->token);
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
        if (! $token = $this->parseAuthHeader()) {
            if (! $token = $this->request->query($query, false)) {
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
    protected function parseAuthHeader($header = 'authorization', $method = 'bearer')
    {
        $header = $this->request->headers->get($header);

        if (! starts_with(strtolower($header), $method)) {
            return false;
        }

        return trim(str_ireplace($method, '', $header));
    }


    /**
     * Parse token from the authorization header
     *
     * @param  mixed  $subject
     * @param  array  $customClaims
     * @return \Tymon\JWTAuth\Payload
     */
    protected function makePayload($subject, array $customClaims = [])
    {
        return $this->manager->getPayloadFactory()->make(array_merge($customClaims, ['sub' => $subject]));
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
        $this->token = new Token($token);

        return $this;
    }

    /**
     * Ensure that a token is available
     *
     * @param  mixed  $token
     * @return void
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function requireToken($token)
    {
        if ($token) {
            return $this->setToken($token);
        } else {
            if (! $this->token) {
                throw new JWTException('A token is required', 400);
            }
        }
    }

    /**
     * Get the JWTManager instance
     *
     * @return \Tymon\JWTAuth\JWTManager
     */
    public function manager()
    {
        return $this->manager;
    }

    /**
     * Magically call the JWT Manager
     *
     * @param  string  $method
     * @param  array   $parameters
     * @return mixed
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
