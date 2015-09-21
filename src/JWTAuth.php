<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Contracts\Providers\Auth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Http\TokenParser;

class JWTAuth
{
    use CustomClaims;

    /**
     * @var \Tymon\JWTAuth\Manager
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
     * @param \Tymon\JWTAuth\Manager                   $manager
     * @param \Tymon\JWTAuth\Contracts\Providers\Auth  $auth
     * @param \Tymon\JWTAuth\Http\TokenParser          $parser
     */
    public function __construct(Manager $manager, Auth $auth, TokenParser $parser)
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

        return $this->fromUser($this->user());
    }

    /**
     * Authenticate a user via a token.
     *
     * @return \Tymon\JWTAuth\Contracts\JWTSubject|false
     */
    public function authenticate()
    {
        $id = $this->getPayload()->get('sub');

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->user();
    }

    /**
     * Alias for authenticate().
     *
     * @return \Tymon\JWTAuth\Contracts\JWTSubject|false
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

        return $this->manager->customClaims($this->getCustomClaims())->refresh($this->token)->get();
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
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted
     *
     * @throws JWTException
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function checkOrFail()
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid
     *
     * @return boolean
     */
    public function check()
    {
        try {
            $this->checkOrFail();
        } catch (JWTException $e) {
            return false;
        }

        return true;
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
            throw new JWTException('The token could not be parsed from the request');
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
        return $this->factory()->customClaims($this->getClaimsArray($user))->make();
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
            ['sub' => $user->getJWTIdentifier()],
            $this->customClaims,
            $user->getJWTCustomClaims()
        );
    }

    /**
     * Get the authenticated user
     *
     * @return \Tymon\JWTAuth\Contracts\JWTSubject
     */
    public function user()
    {
        return $this->auth->user();
    }

    /**
     * Set the token.
     *
     * @param string $token
     *
     * @return JWTAuth
     */
    public function setToken($token)
    {
        $this->token = new Token($token);

        return $this;
    }

    /**
     * Ensure that a token is available.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    protected function requireToken()
    {
        if (! $this->token) {
            throw new JWTException('A token is required');
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
     * Get the Manager instance.
     *
     * @return \Tymon\JWTAuth\Manager
     */
    public function manager()
    {
        return $this->manager;
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
     * Get the Payload Factory
     *
     * @return \Tymon\JWTAuth\Factory
     */
    public function factory()
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist
     *
     * @return \Tymon\JWTAuth\Blacklist
     */
    public function blacklist()
    {
        return $this->manager->getBlacklist();
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
