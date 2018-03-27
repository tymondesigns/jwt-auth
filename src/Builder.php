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

use Illuminate\Support\Arr;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Support\Utils;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Claims\Factory as ClaimFactory;

class Builder
{
    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * The TTL.
     *
     * @var int
     */
    protected $ttl = 30;

    /**
     * Lock the subject.
     *
     * @var bool
     */
    protected $lockSubject = true;

    /**
     * Time leeway in seconds.
     *
     * @var int
     */
    protected $leeway = 0;

    /**
     * Max refresh period in minutes.
     *
     * @var int|null
     */
    protected $maxRefreshPeriod;

    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims;

    /**
     * The default claims to add.
     *
     * @var array
     */
    protected $defaultClaims = [
        'iat',
        'jti',
        'iss',
    ];

    /**
     * Constructor.
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Create a Payload instance.
     */
    public function makePayload(JWTSubject $subject, array $claims = []): Payload
    {
        return Factory::make($this->getClaimsArray($subject, $claims), [
            'leeway' => $this->leeway,
            'required_claims' => $this->requiredClaims,
            'max_refresh_period' => $this->maxRefreshPeriod,
        ]);
    }

    /**
     * Build the claims array and return it.
     */
    protected function getClaimsArray(JWTSubject $subject, array $claims = []): array
    {
        return array_merge(
            $this->getDefaultClaims(),
            $this->getClaimsForSubject($subject),
            $subject->getJWTCustomClaims(), // custom claims from JWTSubject method
            $claims // custom claims from inline setter
        );
    }

    /**
     * Get the default claims to add.
     */
    protected function getDefaultClaims(): array
    {
        if ($key = array_search('iss', $this->defaultClaims)) {
            $iss = Arr::pull($this->defaultClaims, $key);
        }

        return array_merge(
            $this->defaultClaims,
            // only add the iss claim if it exists in the default claims.
            isset($iss) ? [$this->issClaim()] : [],
            // only add exp claim if the ttl is not null
            $this->getTTL() !== null ? [$this->expClaim()] : []
        );
    }

    /**
     * Get the issuer (iss) claim.
     */
    protected function issClaim(): Issuer
    {
        return ClaimFactory::get('iss', $this->request->getHost());
    }

    /**
     * Get the expiration (exp) claim.
     */
    protected function expClaim(): Expiration
    {
        return ClaimFactory::get('exp', Utils::now()->addMinutes($this->getTTL())->getTimestamp(), [
            'leeway' => $this->leeway,
        ]);
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
    public function hashSubjectModel($model): string
    {
        return sha1(is_object($model) ? get_class($model) : $model);
    }

    /**
     * Set the request instance.
     */
    public function setRequest(Request $request): self
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the request instance.
     */
    public function getRequest(): Request
    {
        return $this->request;
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
     * Set the token ttl (in minutes).
     *
     * @param  int|null  $ttl
     */
    public function setTTL(?int $ttl): self
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the token ttl.
     *
     * @return int|null
     */
    public function getTTL(): ?int
    {
        return $this->ttl;
    }

    /**
     * Set the default claims.
     */
    public function setDefaultClaims(array $claims = []): self
    {
        $this->defaultClaims = $claims;

        return $this;
    }

    /**
     * Set the default claims.
     */
    public function setRequiredClaims(array $claims = []): self
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the leeway in seconds.
     */
    public function setLeeway(int $leeway): self
    {
        $this->leeway = $leeway;

        return $this;
    }

    /**
     * Set the max refresh period in minutes.
     *
     * @param int|null $period
     */
    public function setMaxRefreshPeriod(?int $period): self
    {
        $this->maxRefreshPeriod = $period;

        return $this;
    }
}
