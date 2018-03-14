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

namespace Tymon\JWTAuth\Http;

use Tymon\JWTAuth\Token;
use Illuminate\Http\JsonResponse;
use Illuminate\Contracts\Support\Responsable;

class TokenResponse implements Responsable
{
    /**
     * The token itself.
     *
     * @var \Tymon\JWTAuth\Token
     */
    protected $token;

    /**
     * The token ttl.
     *
     * @var int
     */
    protected $ttl;

    /**
     * The token type.
     *
     * @var string
     */
    protected $type;

    /**
     * Constructor.
     */
    public function __construct(Token $token, int $ttl, $type = 'bearer')
    {
        $this->token = $token;
        $this->ttl = $ttl;
        $this->type = $type;
    }

    /**
     * {@inheritdoc}
     */
    public function toResponse($request)
    {
        return new JsonResponse([
            'access_token' => $this->token->get(),
            'token_type' => $this->type,
            'expires_in' => $this->ttl * 60,
        ]);
    }

    /**
     * Get the token when casting to string.
     */
    public function __toString(): string
    {
        return $this->token->get();
    }

    /**
     * Magically call the Token.
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call(string $method, array $parameters)
    {
        if (method_exists($this->token, $method)) {
            return call_user_func_array([$this->token, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
