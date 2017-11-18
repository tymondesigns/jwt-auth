<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use BadMethodCallException;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Support\CustomClaims;

class JWT
{
    use CustomClaims;

    /**
     * The authentication manager.
     *
     * @var \Tymon\JWTAuth\Manager
     */
    protected $manager;

    /**
     * The HTTP parser.
     *
     * @var \Tymon\JWTAuth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * The token.
     *
     * @var \Tymon\JWTAuth\Token|null
     */
    protected $token;

    /**
     * JWT constructor.
     *
     * @param  \Tymon\JWTAuth\Manager  $manager
     * @param  \Tymon\JWTAuth\Http\Parser\Parser  $parser
     */
    public function __construct(Manager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token for a given subject.
     *
     * @param  \Tymon\JWTAuth\Contracts\JWTSubject  $subject
     */
    public function fromSubject(JWTSubject $subject): string
    {
        $payload = $this->makePayload($subject);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Alias to generate a token for a given user.
     *
     * @param  \Tymon\JWTAuth\Contracts\JWTSubject  $user
     */
    public function fromUser(JWTSubject $user): string
    {
        return $this->fromSubject($user);
    }

    /**
     * Refresh an expired token.
     */
    public function refresh(bool $forceForever = false, bool $resetClaims = false): string
    {
        $this->requireToken();

        return $this->manager->customClaims($this->getCustomClaims())
                             ->refresh($this->token, $forceForever, $resetClaims)
                             ->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     *
     *
     * @return $this
     */
    public function invalidate(bool $forceForever = false)
    {
        $this->requireToken();

        $this->manager->invalidate($this->token, $forceForever);

        return $this;
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function checkOrFail(): \Tymon\JWTAuth\Payload
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     *
     *
     * @return \Tymon\JWTAuth\Payload|bool
     */
    public function check(bool $getPayload = false)
    {
        try {
            $payload = $this->checkOrFail();
        } catch (JWTException $e) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    /**
     * Get the token.
     *
     * @return \Tymon\JWTAuth\Token|false
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
     * @return $this
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
     */
    public function getPayload(): \Tymon\JWTAuth\Payload
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
    }

    /**
     * Alias for getPayload().
     */
    public function payload(): \Tymon\JWTAuth\Payload
    {
        return $this->getPayload();
    }

    /**
     * Convenience method to get a claim value.
     *
     *
     * @return mixed
     */
    public function getClaim(string $claim)
    {
        return $this->payload()->get($claim);
    }

    /**
     * Create a Payload instance.
     *
     * @param  \Tymon\JWTAuth\Contracts\JWTSubject  $subject
     */
    public function makePayload(JWTSubject $subject): \Tymon\JWTAuth\Payload
    {
        return $this->factory()->customClaims($this->getClaimsArray($subject))->make();
    }

    /**
     * Build the claims array and return it.
     *
     * @param  \Tymon\JWTAuth\Contracts\JWTSubject  $subject
     */
    protected function getClaimsArray(JWTSubject $subject): array
    {
        return array_merge(
            $this->getClaimsForSubject($subject),
            $subject->getJWTCustomClaims(), // custom claims from JWTSubject method
            $this->customClaims // custom claims from inline setter
        );
    }

    /**
     * Get the claims associated with a given subject.
     *
     * @param  \Tymon\JWTAuth\Contracts\JWTSubject  $subject
     */
    protected function getClaimsForSubject(JWTSubject $subject): array
    {
        return [
            'sub' => $subject->getJWTIdentifier(),
            'prv' => $this->hashProvider($subject),
        ];
    }

    /**
     * Hash the provider and return it.
     *
     * @param  string|object  $provider
     */
    protected function hashProvider($provider): string
    {
        return sha1(is_object($provider) ? get_class($provider) : $provider);
    }

    /**
     * Check if the provider matches the one saved in the token.
     *
     * @param  string|object  $provider
     */
    public function checkProvider($provider): bool
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashProvider($provider) === $prv;
    }

    /**
     * Set the token.
     *
     * @param  \Tymon\JWTAuth\Token|string  $token
     *
     * @return $this
     */
    public function setToken($token)
    {
        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    /**
     * Unset the current token.
     *
     * @return $this
     */
    public function unsetToken()
    {
        $this->token = null;

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
     * @param  \Illuminate\Http\Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Get the Manager instance.
     */
    public function manager(): \Tymon\JWTAuth\Manager
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     */
    public function parser(): \Tymon\JWTAuth\Http\Parser\Parser
    {
        return $this->parser;
    }

    /**
     * Get the Payload Factory.
     */
    public function factory(): \Tymon\JWTAuth\Factory
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist.
     */
    public function blacklist(): \Tymon\JWTAuth\Blacklist
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Magically call the JWT Manager.
     *
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call(string $method, array $parameters)
    {
        if (method_exists($this->manager, $method)) {
            return call_user_func_array([$this->manager, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
