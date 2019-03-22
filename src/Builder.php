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
use function Tymon\JWTAuth\Support\now;
use Tymon\JWTAuth\Contracts\JWTSubject;
use function Tymon\JWTAuth\Support\timestamp;
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
     * The TTL in minutes.
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
        Claims\IssuedAt::NAME,
        Claims\JwtId::NAME,
        Claims\Issuer::NAME,
    ];

    /**
     * Any custom validators.
     *
     * @var array
     */
    protected $customValidators = [];

    /**
     * Constructor.
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Create a Payload instance for a given array of claims.
     */
    public function make(array $claims = []): Payload
    {
        return Factory::make($claims, $this->getOptions());
    }

    /**
     * Create a Payload instance for a given subject.
     */
    public function makeForSubject(JWTSubject $subject, array $claims = []): Payload
    {
        return $this->make(array_merge(
            $this->getDefaultClaims(),
            $this->getClaimsForSubject($subject),
            $subject->getJWTCustomClaims(), // custom claims from JWTSubject method
            $claims // custom claims from inline setter
        ));
    }

    /**
     * Build the claims to go into the refreshed token.
     */
    public function buildRefreshClaims(Payload $payload): array
    {
        return array_merge($payload->toArray(), [
            Claims\JwtId::NAME => ClaimFactory::get(Claims\JwtId::NAME),
            Claims\Expiration::NAME => timestamp($payload[Claims\Expiration::NAME])
                ->addMinutes($this->getTTL())
                ->getTimestamp(),
        ]);
    }

    /**
     * Get the builder options.
     */
    public function getOptions(): Options
    {
        return new Options([
            Options::LEEWAY => $this->leeway,
            Options::REQUIRED_CLAIMS => $this->requiredClaims,
            Options::MAX_REFRESH_PERIOD => $this->maxRefreshPeriod,
            Options::VALIDATORS => $this->customValidators,
        ]);
    }

    /**
     * Get the default claims to add.
     */
    protected function getDefaultClaims(): array
    {
        if ($key = array_search(Claims\Issuer::NAME, $this->defaultClaims)) {
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
    protected function issClaim(): Claims\Issuer
    {
        return ClaimFactory::get(
            Claims\Issuer::NAME,
            $this->request->getHost(),
            $this->getOptions()
        );
    }

    /**
     * Get the expiration (exp) claim.
     */
    protected function expClaim(): Claims\Expiration
    {
        return ClaimFactory::get(
            Claims\Expiration::NAME,
            now()->addMinutes($this->getTTL())->getTimestamp(),
            $this->getOptions()
        );
    }

    /**
     * Get the claims associated with a given subject.
     */
    protected function getClaimsForSubject(JWTSubject $subject): array
    {
        return array_merge([
            Claims\Subject::NAME => $subject->getJWTIdentifier(),
        ], $this->lockSubject ? [
            Claims\HashedSubject::NAME => $this->hashSubjectModel($subject),
        ] : []);
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
     */
    public function setTTL(?int $ttl): self
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the token ttl.
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
     */
    public function setMaxRefreshPeriod(?int $period): self
    {
        $this->maxRefreshPeriod = $period;

        return $this;
    }

    /**
     * Add a custom validator.
     */
    public function setCustomValidator(string $key, callable $validator): self
    {
        $this->customValidators[$key] = $validator;

        return $this;
    }
}
