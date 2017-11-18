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

use Tymon\JWTAuth\Claims\Claim;
use Tymon\JWTAuth\Claims\Collection;
use Tymon\JWTAuth\Claims\Factory as ClaimFactory;
use Tymon\JWTAuth\Support\CustomClaims;
use Tymon\JWTAuth\Support\RefreshFlow;
use Tymon\JWTAuth\Validators\PayloadValidator;

class Factory
{
    use CustomClaims, RefreshFlow;

    /**
     * The claim factory.
     *
     * @var \Tymon\JWTAuth\Claims\Factory
     */
    protected $claimFactory;

    /**
     * The validator.
     *
     * @var \Tymon\JWTAuth\Validators\PayloadValidator
     */
    protected $validator;

    /**
     * The default claims.
     *
     * @var array
     */
    protected $defaultClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'jti',
    ];

    /**
     * The claims collection.
     *
     * @var \Tymon\JWTAuth\Claims\Collection
     */
    protected $claims;

    /**
     * Constructor.
     *
     * @param  \Tymon\JWTAuth\Claims\Factory  $claimFactory
     * @param  \Tymon\JWTAuth\Validators\PayloadValidator  $validator
     *
     */
    public function __construct(ClaimFactory $claimFactory, PayloadValidator $validator)
    {
        $this->claimFactory = $claimFactory;
        $this->validator = $validator;
        $this->claims = new Collection;
    }

    /**
     * Create the Payload instance.
     *
     * @param  bool  $resetClaims
     *
     */
    public function make(bool $resetClaims = false): \Tymon\JWTAuth\Payload
    {
        $payload = $this->withClaims($this->buildClaimsCollection());

        if ($resetClaims) {
            $this->emptyClaims();
        }

        return $payload;
    }

    /**
     * Empty the claims collection.
     *
     * @return $this
     */
    public function emptyClaims()
    {
        $this->claims = new Collection;

        return $this;
    }

    /**
     * Add an array of claims to the Payload.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    protected function addClaims(array $claims)
    {
        foreach ($claims as $name => $value) {
            $this->addClaim($name, $value);
        }

        return $this;
    }

    /**
     * Add a claim to the Payload.
     *
     * @param  string  $name
     * @param  mixed  $value
     *
     * @return $this
     */
    protected function addClaim(string $name, $value)
    {
        $this->claims->put($name, $value);

        return $this;
    }

    /**
     * Build the default claims.
     *
     * @return $this
     */
    protected function buildClaims()
    {
        // remove the exp claim if it exists and the ttl is null
        if ($this->claimFactory->getTTL() === null && $key = array_search('exp', $this->defaultClaims)) {
            unset($this->defaultClaims[$key]);
        }

        // add the default claims
        foreach ($this->defaultClaims as $claim) {
            $this->addClaim($claim, $this->claimFactory->make($claim));
        }

        // add custom claims on top, allowing them to overwrite defaults
        return $this->addClaims($this->getCustomClaims());
    }

    /**
     * Build out the Claim DTO's.
     *
     */
    protected function resolveClaims(): \Tymon\JWTAuth\Claims\Collection
    {
        return $this->claims->map(function ($value, $name) {
            return $value instanceof Claim ? $value : $this->claimFactory->get($name, $value);
        });
    }

    /**
     * Build and get the Claims Collection.
     *
     */
    public function buildClaimsCollection(): \Tymon\JWTAuth\Claims\Collection
    {
        return $this->buildClaims()->resolveClaims();
    }

    /**
     * Get a Payload instance with a claims collection.
     *
     * @param  \Tymon\JWTAuth\Claims\Collection  $claims
     *
     */
    public function withClaims(Collection $claims): \Tymon\JWTAuth\Payload
    {
        return new Payload($claims, $this->validator, $this->refreshFlow);
    }

    /**
     * Set the default claims to be added to the Payload.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setDefaultClaims(array $claims)
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * Helper to set the ttl.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setTTL(int $ttl)
    {
        $this->claimFactory->setTTL($ttl);

        return $this;
    }

    /**
     * Helper to get the ttl.
     *
     */
    public function getTTL(): int
    {
        return $this->claimFactory->getTTL();
    }

    /**
     * Get the default claims.
     *
     * @return array
     */
    public function getDefaultClaims(): array
    {
        return $this->defaultClaims;
    }

    /**
     * Get the PayloadValidator instance.
     *
     */
    public function validator(): \Tymon\JWTAuth\Validators\PayloadValidator
    {
        return $this->validator;
    }

    /**
     * Magically add a claim.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @return $this
     */
    public function __call(string $method, array $parameters)
    {
        $this->addClaim($method, $parameters[0]);

        return $this;
    }
}
