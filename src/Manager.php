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

use Tymon\JWTAuth\Support\Utils;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Claims\Factory as ClaimFactory;
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
     * The blacklist flag.
     *
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * Constructor.
     */
    public function __construct(JWTContract $provider, Blacklist $blacklist)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
    }

    /**
     * Encode a Payload and return the Token.
     */
    public function encode(Payload $payload): Token
    {
        return $this->provider->token($payload->get());
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenBlacklistedException
     */
    public function decode(Token $token, bool $checkBlacklist = true): Payload
    {
        $payload = $this->provider->payload($token->get());

        if ($checkBlacklist && $this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException();
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     */
    public function refresh(Token $token, int $ttl): Token
    {
        // Get the claims for the new token
        $claims = $this->buildRefreshClaims($this->decode($token), $ttl);

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token);
        }

        // Return the new token
        return $this->encode(Factory::make($claims));
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function invalidate(Token $token): bool
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        return $this->blacklist->add($this->decode($token, false));
    }

    /**
     * Build the claims to go into the refreshed token.
     */
    protected function buildRefreshClaims(Payload $payload, int $ttl): array
    {
        return array_merge($payload->toArray(), [
            'jti' => ClaimFactory::get('jti'),
            'exp' => Utils::timestamp($payload['exp'])->addMinutes($ttl)->getTimestamp(),
        ]);
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
     * Set whether the blacklist is enabled.
     */
    public function setBlacklistEnabled(bool $enabled): self
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Set the claims to be persisted when refreshing a token.
     */
    public function setPersistentClaims(array $claims): self
    {
        $this->persistentClaims = $claims;

        return $this;
    }
}
