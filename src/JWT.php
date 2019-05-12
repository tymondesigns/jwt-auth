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

use Illuminate\Http\Request;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Claims\HashedSubject;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Traits\ForwardsCalls;

class JWT
{
    use CustomClaims;
    use ForwardsCalls;

    /**
     * The payload builder.
     *
     * @var \Tymon\JWTAuth\Builder
     */
    protected $builder;

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
     */
    public function __construct(Builder $builder, Manager $manager, Parser $parser)
    {
        $this->builder = $builder;
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token for a given subject.
     */
    public function fromSubject(JWTSubject $subject): Token
    {
        return $this->manager->tokenForSubject($subject, $this->customClaims);
    }

    /**
     * Alias to generate a token for a given user.
     */
    public function fromUser(JWTSubject $user): Token
    {
        return $this->fromSubject($user);
    }

    /**
     * Invalidate a token (add it to the blacklist).
     */
    public function invalidate(): self
    {
        $this->requireToken();

        $this->manager->invalidate($this->token);

        return $this;
    }

    /**
     * Refresh a token.
     */
    public function refresh(): Token
    {
        $this->requireToken();

        return $this->manager->refresh($this->token);
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function checkOrFail(): Payload
    {
        return $this->payload();
    }

    /**
     * Check that the token is valid.
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
     */
    public function getToken(bool $fresh = false): ?Token
    {
        if ($this->token === null || $fresh === true) {
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
    public function payload(): Payload
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
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
     * Check if the subject model matches the one saved in the payload.
     */
    public function checkSubjectModel($model, ?Payload $payload = null): bool
    {
        $payload = $payload ?? $this->payload();

        if (! $hash = $payload->get(HashedSubject::NAME)) {
            return true;
        }

        return $this->builder->hashSubjectModel($model) === $hash;
    }

    /**
     * Set the token.
     *
     * @param  \Tymon\JWTAuth\Token|string  $token
     */
    public function setToken($token): self
    {
        $this->token = $token instanceof Token
            ? $token
            : new Token($token);

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
    protected function requireToken(): void
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
        $this->builder->setRequest($request);
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Get the Builder instance.
     */
    public function builder(): Builder
    {
        return $this->builder;
    }

    /**
     * Get the Manager instance.
     */
    public function manager(): Manager
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     *
     * @return \Tymon\JWTAuth\Http\Parser\Parser|\Tymon\JWTAuth\Contracts\Http\Parser
     */
    public function parser(?string $key = null)
    {
        return $key === null
            ? $this->parser
            : $this->parser->get($key);
    }

    /**
     * Get the Blacklist.
     */
    public function blacklist(): Blacklist
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Set the token ttl (in minutes).
     */
    public function setTTL(?int $ttl): self
    {
        $this->builder->setTTL($ttl);

        return $this;
    }

    /**
     * Get the token ttl.
     */
    public function getTTL(): ?int
    {
        return $this->builder->getTTL();
    }

    /**
     * Set the secret.
     */
    public function setSecret(string $secret): self
    {
        $this->manager->getJWTProvider()
            ->setSecret($secret);

        return $this;
    }

    /**
     * Set the required claims.
     */
    public function setRequiredClaims(array $claims = []): self
    {
        $this->builder->setRequiredClaims($claims);

        return $this;
    }

    /**
     * Register a custom claim validator.
     */
    public function registerCustomValidator(string $key, callable $validator): self
    {
        $this->builder->setCustomValidator($key, $validator);

        return $this;
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
        return $this->forwardCallTo($this->manager, $method, $parameters);
    }
}
