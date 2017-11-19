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

namespace Tymon\JWTAuth\Claims;

use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Support\Utils;

class Factory
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
    protected $ttl = 60;

    /**
     * The classes map.
     *
     * @var array
     */
    private $classMap = [
        'aud' => Audience::class,
        'exp' => Expiration::class,
        'iat' => IssuedAt::class,
        'iss' => Issuer::class,
        'jti' => JwtId::class,
        'nbf' => NotBefore::class,
        'sub' => Subject::class,
    ];

    /**
     * Constructor.
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Get the instance of the claim when passing the name and value.
     *
     * @param  mixed  $value
     */
    public function get(string $name, $value): \Tymon\JWTAuth\Claims\Claim
    {
        if ($this->has($name)) {
            return new $this->classMap[$name]($value);
        }

        return new Custom($name, $value);
    }

    /**
     * Check whether the claim exists.
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->classMap);
    }

    /**
     * Generate the initial value and return the Claim instance.
     */
    public function make(string $name): \Tymon\JWTAuth\Claims\Claim
    {
        return $this->get($name, $this->$name());
    }

    /**
     * Get the Issuer (iss) claim.
     */
    public function iss(): string
    {
        return $this->request->url();
    }

    /**
     * Get the Issued At (iat) claim.
     */
    public function iat(): int
    {
        return Utils::now()->getTimestamp();
    }

    /**
     * Get the Expiration (exp) claim.
     */
    public function exp(): int
    {
        return Utils::now()->addMinutes($this->ttl)->getTimestamp();
    }

    /**
     * Get the Not Before (nbf) claim.
     */
    public function nbf(): int
    {
        return Utils::now()->getTimestamp();
    }

    /**
     * Get the JWT Id (jti) claim.
     */
    public function jti(): string
    {
        return Str::random();
    }

    /**
     * Add a new claim mapping.
     *
     * @return $this
     */
    public function extend(string $name, string $classPath)
    {
        $this->classMap[$name] = $classPath;

        return $this;
    }

    /**
     * Set the request instance.
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Set the token ttl (in minutes).
     *
     * @return $this
     */
    public function setTTL(int $ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    /**
     * Get the token ttl.
     *
     * @return int|null
     */
    public function getTTL()
    {
        return $this->ttl;
    }
}
