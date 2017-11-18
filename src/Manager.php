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

use Tymon\JWTAuth\Contracts\Providers\JWT as JWTContract;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Support\RefreshFlow;

class Manager
{
    use CustomClaims, RefreshFlow;

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
     * the payload factory.
     *
     * @var \Tymon\JWTAuth\Factory
     */
    protected $payloadFactory;

    /**
     * The blacklist flag.
     *
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * the persistent claims.
     *
     * @var array
     */
    protected $persistentClaims = [];

    /**
     * Constructor.
     *
     * @param  \Tymon\JWTAuth\Contracts\Providers\JWT  $provider
     * @param  \Tymon\JWTAuth\Blacklist  $blacklist
     * @param  \Tymon\JWTAuth\Factory  $payloadFactory
     */
    public function __construct(JWTContract $provider, Blacklist $blacklist, Factory $payloadFactory)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     */
    public function encode(Payload $payload): \Tymon\JWTAuth\Token
    {
        $token = $this->provider->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\TokenBlacklistedException
     */
    public function decode(Token $token, bool $checkBlacklist = true): \Tymon\JWTAuth\Payload
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
                        ->setRefreshFlow($this->refreshFlow)
                        ->customClaims($payloadArray)
                        ->make();

        if ($checkBlacklist && $this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     */
    public function refresh(Token $token, bool $forceForever = false, bool $resetClaims = false): \Tymon\JWTAuth\Token
    {
        $this->setRefreshFlow();

        $claims = $this->buildRefreshClaims($this->decode($token));

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token, $forceForever);
        }

        // Return the new token
        return $this->encode(
            $this->payloadFactory->customClaims($claims)->make($resetClaims)
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @param  \Tymon\JWTAuth\Token  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function invalidate(Token $token, bool $forceForever = false): bool
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        return call_user_func(
            [$this->blacklist, $forceForever ? 'addForever' : 'add'],
            $this->decode($token, false)
        );
    }

    /**
     * Build the claims to go into the refreshed token.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     */
    protected function buildRefreshClaims(Payload $payload): array
    {
        // assign the payload values as variables for use later
        extract($payload->toArray());

        // persist the relevant claims
        return array_merge(
            $this->customClaims,
            compact($this->persistentClaims, 'sub', 'iat')
        );
    }

    /**
     * Get the Payload Factory instance.
     */
    public function getPayloadFactory(): \Tymon\JWTAuth\Factory
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWTProvider instance.
     */
    public function getJWTProvider(): \Tymon\JWTAuth\Contracts\Providers\JWT
    {
        return $this->provider;
    }

    /**
     * Get the Blacklist instance.
     */
    public function getBlacklist(): \Tymon\JWTAuth\Blacklist
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     *
     *
     * @return $this
     */
    public function setBlacklistEnabled(bool $enabled)
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Set the claims to be persisted when refreshing a token.
     *
     *
     * @return $this
     */
    public function setPersistentClaims(array $claims)
    {
        $this->persistentClaims = $claims;

        return $this;
    }
}
