<?php

declare(strict_types=1);

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
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Exceptions\JWTException;

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
     * Lock the subject.
     *
     * @var bool
     */
    protected $lockSubject = true;

    /**
     * JWT constructor.
     */
    public function __construct(Manager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token for a given subject.
     */
    public function fromSubject(JWTSubject $subject): string
    {
        $payload = $this->makePayload($subject);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Alias to generate a token for a given user.
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
     */
    public function invalidate(bool $forceForever = false): self
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
    public function checkOrFail(): Payload
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     *
     * @param  bool  $getPayload
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
     * @return \Tymon\JWTAuth\Token|null
     */
    public function getToken()
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch (JWTException $e) {
                $this->token = null;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function parseToken(): self
    {
        if (! $token = $this->parser->parseToken()) {
            throw new JWTException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }

    /**
     * Get the raw Payload instance.
     */
    public function getPayload(): Payload
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
    }

    /**
     * Alias for getPayload().
     */
    public function payload(): Payload
    {
        return $this->getPayload();
    }

    /**
     * Convenience method to get a claim value.
     *
     * @return mixed
     */
    public function getClaim(string $claim)
    {
        return $this->payload()->get($claim);
    }

    /**
     * Create a Payload instance.
     */
    public function makePayload(JWTSubject $subject): Payload
    {
        return $this->factory()->customClaims($this->getClaimsArray($subject))->make();
    }

    /**
     * Build the claims array and return it.
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
     */
    protected function getClaimsForSubject(JWTSubject $subject): array
    {
        return array_merge([
            'sub' => $subject->getJWTIdentifier(),
        ], $this->lockSubject ? ['prv' => $this->hashSubjectModel($subject)] : []);
    }

    /**
     * Hash the subject model and return it.
     *
     * @param  string|object  $model
     */
    protected function hashSubjectModel($model): string
    {
        return sha1(is_object($model) ? get_class($model) : $model);
    }

    /**
     * Check if the subject model matches the one saved in the token.
     *
     * @param  string|object  $model
     */
    public function checkSubjectModel($model): bool
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashSubjectModel($model) === $prv;
    }

    /**
     * Set the token.
     *
     * @param  \Tymon\JWTAuth\Token|string  $token
     */
    public function setToken($token): self
    {
        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    /**
     * Unset the current token.
     */
    public function unsetToken(): self
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
     */
    public function setRequest(Request $request): self
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Set whether the subject should be "locked".
     */
    public function lockSubject(bool $lock): self
    {
        $this->lockSubject = $lock;

        return $this;
    }

    /**
     * Get the Manager instance.
     *
     * @return \Tymon\JWTAuth\Manager
     */
    public function manager(): Manager
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     *
     * @return \Tymon\JWTAuth\Http\Parser\Parser
     */
    public function parser(): Parser
    {
        return $this->parser;
    }

    /**
     * Get the Payload Factory.
     *
     * @return \Tymon\JWTAuth\Factory
     */
    public function factory(): Factory
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist.
     *
     * @return \Tymon\JWTAuth\Blacklist
     */
    public function blacklist(): Blacklist
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Magically call the JWT Manager.
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
