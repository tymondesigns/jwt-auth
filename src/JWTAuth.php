<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Providers\Auth\AuthInterface;
use Tymon\JWTAuth\Providers\User\UserInterface;

class JWTAuth
{
    /**
     * @var \Tymon\JWTAuth\JWTManager
     */
    protected $manager;

    /**
     * @var \Tymon\JWTAuth\Providers\User\UserInterface
     */
    protected $user;

    /**
     * @var \Tymon\JWTAuth\Providers\Auth\AuthInterface
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
     * @var \Tymon\JWTAuth\Token
     */
    protected $token;

    /**
     * @param \Tymon\JWTAuth\JWTManager                   $manager
     * @param \Tymon\JWTAuth\Providers\User\UserInterface $user
     * @param \Tymon\JWTAuth\Providers\Auth\AuthInterface $auth
     * @param \Illuminate\Http\Request                    $request
     */
    public function __construct(JWTManager $manager, UserInterface $user, AuthInterface $auth, Request $request)
    {
        $this->manager = $manager;
        $this->user = $user;
        $this->auth = $auth;
        $this->request = $request;
    }

    /**
     * Find a user using the user identifier in the subject claim.
     *
     * @param bool|string $token
     *
     * @return mixed
     */
    public function toUser($token = false)
    {
        $payload = $this->getPayload($token);

        if (! $user = $this->user->getBy($this->identifier, $payload['sub'])) {
            return false;
        }

        return $user;
    }

    /**
     * Generate a token using the user identifier as the subject claim.
     *
     * @param mixed $user
     * @param array $customClaims
     *
     * @return string
     */
    public function fromUser($user, array $customClaims = [])
    {
        $payload = $this->makePayload($user->{$this->identifier}, $customClaims);

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
     * @param mixed $token
     *
     * @return mixed
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
     * @return bool
     */
    public function invalidate($token = false)
    {
        $this->requireToken($token);

        return $this->manager->invalidate($this->token);
    }

    /**
     * Get the token.
     *
     * @return bool|string
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
     * @param string $query
     *
     * @return JWTAuth
     */
    public function parseToken($method = 'bearer', $header = 'authorization', $query = 'token')
    {
        if (! $token = $this->parseAuthHeader($header, $method)) {
            if (! $token = $this->request->query($query, false)) {
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

        if (! starts_with(strtolower($header), $method)) {
            return false;
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
     *
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
