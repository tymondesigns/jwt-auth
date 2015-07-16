<?php

namespace Tymon\JWTAuth\Test\Http;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Http\TokenParser;

class TokenParserTest extends \PHPUnit_Framework_TestCase
{
    /** @test */
    public function it_should_return_the_token_from_the_authorization_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Bearer foobar');

        $parser = new TokenParser($request);

        $this->assertEquals($parser->parseToken(), 'foobar');
    }

    /** @test */
    public function it_should_return_the_token_from_the_alt_authorization_headers()
    {
        $request1 = Request::create('foo', 'POST');
        $request1->server->set('HTTP_AUTHORIZATION', 'Bearer foobar');

        $request2 = Request::create('foo', 'POST');
        $request2->server->set('REDIRECT_HTTP_AUTHORIZATION', 'Bearer foobarbaz');

        $parser = new TokenParser($request1);
        $this->assertEquals($parser->parseToken(), 'foobar');

        $parser->setRequest($request2);
        $this->assertEquals($parser->parseToken(), 'foobarbaz');
    }

    /** @test */
    public function it_should_return_the_token_from_query_string()
    {
        $request = Request::create('foo', 'GET', ['token' => 'foobar']);

        $parser = new TokenParser($request);

        $this->assertEquals($parser->parseToken(), 'foobar');
    }

    /** @test */
    public function it_should_return_false_if_no_token_in_request()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);

        $parser = new TokenParser($request);

        $this->assertFalse($parser->hasToken());
    }
}
