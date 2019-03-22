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

use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Contracts\Providers\JWT as JWTContract;

class Manager
{
    use CustomClaims;

    /**
     * The provider.
     *
     * @var \Tymon\JWTAuth\Contracts\Providers\JWT
     */
    protected $provider;

    /**
     * The blacklist.
     *
     * @var \Tymon\JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * The payload builder.
     *
     * @var \Tymon\JWTAuth\Builder
     */
    protected $builder;

    /**
     * The blacklist flag.
     *
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * Constructor.
     */
    public function __construct(JWTContract $provider, Blacklist $blacklist, Builder $builder)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
        $this->builder = $builder;
    }

    /**
     * Encode a Payload and return the Token.
     */
    public function encode(Payload $payload): Token
    {
        return $this->provider->token($payload);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenBlacklistedException
     */
    public function decode(Token $token, bool $checkBlacklist = true): Payload
    {
        $payload = $this->provider->payload($token, $this->builder->getOptions());

        if ($checkBlacklist && $this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException();
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     */
    public function refresh(Token $token): Token
    {
        // Get the claims for the new token
        $claims = $this->builder->buildRefreshClaims($this->decode($token));

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token);
        }

        // Return the new token
        return $this->encode($this->builder->make($claims));
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function invalidate(Token $token): void
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        $this->blacklist->add($this->decode($token, false));
    }

    /**
     * Get a token for the given subject and claims.
     */
    public function tokenForSubject(JWTSubject $subject, array $claims = []): Token
    {
        $payload = $this->builder->makeForSubject($subject, $claims);

        return $this->encode($payload);
    }

    /**
     * Get the JWTProvider instance.
     */
    public function getJWTProvider(): JWTContract
    {
        return $this->provider;
    }

    /**
     * Get the Blacklist instance.
     */
    public function getBlacklist(): Blacklist
    {
        return $this->blacklist;
    }

    /**
     * Get the Builder instance.
     */
    public function builder(): Builder
    {
        return $this->builder;
    }

    /**
     * Set whether the blacklist is enabled.
     */
    public function setBlacklistEnabled(bool $enabled): self
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }
}
