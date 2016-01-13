<?php

/*
 * This file is part of jwt-auth
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Http;

use Mockery;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Http\Parser;
use Tymon\JWTAuth\Http\AuthHeaders;
use Tymon\JWTAuth\Http\QueryString;
use Tymon\JWTAuth\Http\RouteParams;

class ParserTest extends \PHPUnit_Framework_TestCase
{
    /** @test */
    public function it_should_return_the_token_from_the_authorization_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChainOrder([
            new QueryString,
            new AuthHeaders,
            new RouteParams
        ]);

        $this->assertEquals($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_alt_authorization_headers()
    {
        $request1 = Request::create('foo', 'POST');
        $request1->server->set('HTTP_AUTHORIZATION', 'Bearer foobar');

        $request2 = Request::create('foo', 'POST');
        $request2->server->set('REDIRECT_HTTP_AUTHORIZATION', 'Bearer foobarbaz');

        $parser = new Parser($request1, [
            new AuthHeaders,
            new QueryString,
            new RouteParams
        ]);

        $this->assertEquals($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());

        $parser->setRequest($request2);
        $this->assertEquals($parser->parseToken(), 'foobarbaz');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_query_string()
    {
        $request = Request::create('foo', 'GET', ['token' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChainOrder([
            new AuthHeaders,
            new QueryString,
            new RouteParams
        ]);

        $this->assertEquals($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_route()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return $this->getRouteMock('foobar');
        });

        $parser = new Parser($request);
        $parser->setChainOrder([
            new AuthHeaders,
            new QueryString,
            new RouteParams
        ]);

        $this->assertEquals($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_routeless_requests()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return null;
        });

        $parser = new Parser($request);
        $parser->setChainOrder([
            new AuthHeaders,
            new QueryString,
            new RouteParams
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_lumen_request_arrays()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return [false, ['uses'=>'someController'], ['token'=>'foobar']];
        });

        $parser = new Parser($request);
        $parser->setChainOrder([
            new AuthHeaders,
            new QueryString,
            new RouteParams
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_return_null_if_no_token_in_request()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return $this->getRouteMock();
        });

        $parser = new Parser($request);
        $parser->setChainOrder([
            new AuthHeaders,
            new QueryString,
            new RouteParams
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_retrieve_the_chain()
    {
        $chain = [
            new AuthHeaders,
            new QueryString,
            new RouteParams
        ];

        $parser = new Parser(Mockery::mock('Illuminate\Http\Request'));
        $parser->setChain($chain);

        $this->assertEquals($parser->getChain(), $chain);
    }

    protected function getRouteMock($expectedParameterValue = null)
    {
        return Mockery::mock('Illuminate\Routing\Route')
            ->shouldReceive('parameter')
            ->with('token')
            ->andReturn($expectedParameterValue)
            ->getMock();
    }
}
