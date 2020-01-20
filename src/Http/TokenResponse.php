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

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Traits\ForwardsCalls;
use Tymon\JWTAuth\Token;

class TokenResponse implements Responsable
{
    use ForwardsCalls;

    /**
     * The token itself.
     */
    protected Token $token;

    /**
     * The token ttl.
     */
    protected int $ttl;

    /**
     * The token type.
     */
    protected string $type;

    /**
     * Constructor.
     */
    public function __construct(Token $token, int $ttl, string $type = 'bearer')
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
        return $this->forwardCallTo($this->token, $method, $parameters);
    }
}
