<?php

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Contracts\Providers\Auth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Http\TokenParser;

class JWTAuth
{
    /**
     * @var \Tymon\JWTAuth\JWTManager
     */
    protected $manager;

    /**
     * @var \Tymon\JWTAuth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * @var \Tymon\JWTAuth\Http\TokenParser
     */
    protected $parser;

    /**
     * @var \Tymon\JWTAuth\Token
     */
    protected $token;

    /**
     * Custom claims
     *
     * @var array
     */
    protected $customClaims = [];

    /**
     * @param \Tymon\JWTAuth\JWTManager                $manager
     * @param \Tymon\JWTAuth\Contracts\Providers\Auth  $auth
     * @param \Tymon\JWTAuth\Http\TokenParser          $parser
     */
    public function __construct(JWTManager $manager, Auth $auth, TokenParser $parser)
    {
        $this->manager = $manager;
        $this->auth = $auth;
        $this->parser = $parser;
    }

    /**
     * Generate a token using the user identifier as the subject claim.
     *
     * @param \Tymon\JWTAuth\Contracts\JWTSubject $user
     *
     * @return string
     */
    public function fromUser(JWTSubject $user)
    {
        $payload = $this->makePayload($user);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Attempt to authenticate the user and return the token.
     *
     * @param array $credentials
     *
     * @return false|string
     */
    public function attempt(array $credentials)
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->auth->user());
    }

    /**
     * Authenticate a user via a token.
     *
     * @return \Tymon\JWTAuth\JWTSubject|false
     */
    public function authenticate()
    {
        $id = $this->getPayload()->get('sub');

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->auth->user();
    }

    /**
     * Alias for authenticate().
     *
     * @return \Tymon\JWTAuth\JWTSubject|false
     */
    public function toUser()
    {
        return $this->authenticate();
    }

    /**
     * Refresh an expired token.
     *
     * @return string
     */
    public function refresh()
    {
        $this->requireToken();

        return $this->manager->refresh($this->token, $this->customClaims)->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     *
     * @return boolean
     */
    public function invalidate()
    {
        $this->requireToken();

        return $this->manager->invalidate($this->token);
    }

    /**
     * Get the token.
     *
     * @return false|Token
     */
    public function getToken()
    {
        if (! $this->token) {
            try {
                $this->parseToken();
            } catch (JWTException $e) {
                return false;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return JWTAuth
     */
    public function parseToken()
    {
        if (! $token = $this->parser->parseToken()) {
            throw new JWTException('The token could not be parsed from the request', 400);
        }

        return $this->setToken($token);
    }

    /**
     * Get the raw Payload instance.
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function getPayload()
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
    }

    /**
     * Create a Payload instance.
     *
     * @param \Tymon\JWTAuth\Contracts\JWTSubject $user
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function makePayload(JWTSubject $user)
    {
        return $this->factory()->make($this->getClaimsArray($user));
    }

    /**
     * Build the claims array and return it
     *
     * @param \Tymon\JWTAuth\Contracts\JWTSubject $user
     *
     * @return array
     */
    protected function getClaimsArray(JWTSubject $user)
    {
        return array_merge(
            $this->customClaims,
            $user->getJWTCustomClaims(),
            ['sub' => $user->getJWTIdentifier()]
        );
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
     * @return JWTAuth
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function requireToken()
    {
        if (! $this->token) {
            throw new JWTException('A token is required', 400);
        }
    }

    /**
     * Set the request instance.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return JWTAuth
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Set the custom claims.
     *
     * @param array $customClaims
     *
     * @return $this
     */
    public function customClaims(array $customClaims = [])
    {
        $this->customClaims = $customClaims;

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
     * Get the PayloadFactory
     *
     * @return \Tymon\JWTAuth\PayloadFactory
     */
    public function factory()
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the TokenParser instance
     *
     * @return \Tymon\JWTAuth\Http\TokenParser
     */
    public function parser()
    {
        return $this->parser;
    }

    /**
     * Magically call the JWT Manager.
     *
     * @param string $method
     * @param array  $parameters
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
