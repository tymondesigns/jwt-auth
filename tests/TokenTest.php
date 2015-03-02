<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Tymon\JWTAuth\Token;

class TokenTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->token = new Token('foo.bar.baz');
    }

    /** @test */
    public function it_should_return_the_token_when_casting_to_a_string()
    {
        $this->assertEquals((string) $this->token, $this->token);
    }

    /** @test */
    public function it_should_return_the_token_when_calling_get_method()
    {
        $this->assertInternalType('string', $this->token->get());
    }
}
