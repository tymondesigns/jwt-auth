<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\JWTAuthSubject;
use Tymon\JWTAuth\Http\TokenParser;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Providers\Auth\AuthInterface;

class JWTAuth
{
    /**
     * @var \Tymon\JWTAuth\JWTManager
     */
    protected $manager;

    /**
     * @var \Tymon\JWTAuth\Providers\Auth\AuthInterface
     */
    protected $auth;

    /**
     * @var \Tymon\JWTAuth\Token\Http\TokenParser
     */
    protected $parser;

    /**
     * @var \Tymon\JWTAuth\Token
     */
    protected $token;

    /**
     * @param \Tymon\JWTAuth\JWTManager                   $manager
     * @param \Tymon\JWTAuth\Providers\Auth\AuthInterface $auth
     * @param \Tymon\JWTAuth\Token\Http\TokenParser       $parser
     */
    public function __construct(JWTManager $manager, AuthInterface $auth, TokenParser $parser)
    {
        $this->manager = $manager;
        $this->auth = $auth;
        $this->parser = $parser;
    }

    /**
     * Generate a token using the user identifier as the subject claim.
     *
     * @param JWTAuthSubject $user
     * @param array $customClaims
     *
     * @return string
     */
    public function fromUser(JWTAuthSubject $user, array $customClaims = [])
    {
        $payload = $this->makePayload($user, $customClaims);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Attempt to authenticate the user and return the token.
     *
     * @param array $credentials
     * @param array $customClaims
     *
     * @return false|string
     */
    public function attempt(array $credentials = [], array $customClaims = [])
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->auth->user(), $customClaims);
    }

    /**
     * Authenticate a user via a token.
     *
     * @param bool|string $token
     *
     * @return \Tymon\JWTAuth\JWTAuthSubject
     */
    public function authenticate($token = false)
    {
        $id = $this->getPayload($token)->get('sub');

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->auth->user();
    }

    /**
     * Maintaining backwards compatibilty. Alternative for authenticate().
     *
     * @param bool|string $token
     *
     * @return \Tymon\JWTAuth\JWTAuthSubject
     */
    public function toUser($token = false)
    {
        return $this->authenticate($token);
    }

    /**
     * Refresh an expired token.
     *
     * @param mixed $token
     *
     * @return string
     */
    public function refresh($token = false)
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
    public function invalidate($token = false)
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
     * Get the raw Payload instance.
     *
     * @param mixed $token
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function getPayload($token = false)
    {
        $this->requireToken($token);

        return $this->manager->decode($this->token);
    }

    /**
     * Parse the token from the request.
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
     * Create a Payload instance.
     *
     * @param JWTAuthSubject $user
     * @param array $customClaims
     *
     * @return \Tymon\JWTAuth\Payload
     */
    protected function makePayload(JWTAuthSubject $user, array $customClaims = [])
    {
        return $this->manager->getPayloadFactory()->make(
            array_merge($customClaims, $user->getJWTCustomClaims(), ['sub' => $user->getJWTIdentifier()])
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
     * @param mixed $token
     *
     * @return JWTAuth
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function requireToken($token)
    {
        if (! $token = $token ?: $this->token) {
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
        $this->parser->setRequest($request);

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
