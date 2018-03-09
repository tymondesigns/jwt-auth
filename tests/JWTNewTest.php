<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test;

use Mockery;
use Tymon\JWTAuth\JWT;
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Factory;
use Tymon\JWTAuth\Manager;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\Builder;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Blacklist;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Test\Stubs\UserStub;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Contracts\Providers\Auth;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class JWTNewTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Builder
     */
    protected $builder;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Manager
     */
    protected $manager;

    /**
     * @var \Mockery\MockInterface|\Tymon\JWTAuth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * @var \Tymon\JWTAuth\JWT
     */
    protected $jwt;

    public function setUp()
    {
        $this->builder = Mockery::spy(Builder::class);
        $this->manager = Mockery::spy(Manager::class);
        $this->parser = Mockery::spy(Parser::class);
        $this->jwt = new JWT($this->builder, $this->manager, $this->parser);
    }

    /** @test */
    public function it_should_return_a_token_when_passing_a_user()
    {
        $this->builder->shouldReceive('makePayload')
            ->once()
            ->with($user = new UserStub, ['foo' => 'bar'])
            ->andReturn($payload = Mockery::mock(Payload::class));

        $this->manager->shouldReceive('encode')
            ->once()
            ->with($payload)
            ->andReturn(new Token('foo.bar.baz'));

        $token = $this->jwt->claims(['foo' => 'bar'])->fromUser($user);

        $this->assertSame($token, 'foo.bar.baz');
    }
}
