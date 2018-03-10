<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Http;

use Mockery;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Crypt;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Http\Parser\Cookies;
use Tymon\JWTAuth\Test\AbstractTestCase;
use Tymon\JWTAuth\Http\Parser\AuthHeaders;
use Tymon\JWTAuth\Http\Parser\InputSource;
use Tymon\JWTAuth\Http\Parser\QueryString;
use Tymon\JWTAuth\Http\Parser\RouteParams;
use Tymon\JWTAuth\Http\Parser\LumenRouteParams;

class ParserTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_the_token_from_the_authorization_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChain([
            'query' => new QueryString,
            'input' => new InputSource,
            'header' => new AuthHeaders,
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_prefixed_authentication_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Custom foobar');

        $parser = new Parser($request);

        $parser->setChain([
            'query' => new QueryString,
            'input' => new InputSource,
            'header' => new AuthHeaders,
            'route' => new RouteParams,
        ]);

        $parser->get('header')->setHeaderPrefix('Custom');

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_authentication_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('custom_authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChain([
            'query' => new QueryString,
            'input' => new InputSource,
            'header' => (new AuthHeaders)->setHeaderName('custom_authorization'),
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
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
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());

        $parser->setRequest($request2);
        $this->assertSame($parser->parseToken(), 'foobarbaz');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_query_string()
    {
        $request = Request::create('foo', 'GET', ['token' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_query_string()
    {
        $request = Request::create('foo', 'GET', ['custom_token_key' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => (new QueryString)->setKey('custom_token_key'),
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_query_string_not_the_input_source()
    {
        $request = Request::create('foo?token=foobar', 'POST', [], [], [], [], json_encode(['token' => 'foobarbaz']));

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_query_string_not_the_custom_input_source()
    {
        $request = Request::create('foo?custom_token_key=foobar', 'POST', [], [], [], [], json_encode(['custom_token_key' => 'foobarbaz']));

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => (new QueryString)->setKey('custom_token_key'),
            'input' => (new InputSource)->setKey('custom_token_key'),
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_input_source()
    {
        $request = Request::create('foo', 'POST', [], [], [], [], json_encode(['token' => 'foobar']));
        $request->headers->set('Content-Type', 'application/json');

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_input_source()
    {
        $request = Request::create('foo', 'POST', [], [], [], [], json_encode(['custom_token_key' => 'foobar']));
        $request->headers->set('Content-Type', 'application/json');

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => (new InputSource)->setKey('custom_token_key'),
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_an_unencrypted_cookie()
    {
        $request = Request::create('foo', 'POST', [], ['token' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
            new Cookies(false),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_a_crypted_cookie()
    {
        Crypt::shouldReceive('encrypt')
            ->with('foobar')
            ->once()
            ->andReturn('cryptedFoobar');

        $request = Request::create('foo', 'POST', [], ['token' => Crypt::encrypt('foobar')]);

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
            new Cookies(true),
        ]);

        Crypt::shouldReceive('decrypt')
            ->with('cryptedFoobar')
            ->times(2)
            ->andReturn('foobar');

        $this->assertSame($parser->parseToken(), 'foobar');
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
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_route_with_a_custom_param()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return $this->getRouteMock('foobar', 'custom_route_param');
        });

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => (new RouteParams)->setKey('custom_route_param'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_routeless_requests()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            //
        });

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_lumen_request_arrays()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return [false, ['uses' => 'someController'], ['token' => 'foobar']];
        });

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_accept_lumen_request_arrays_with_special_class()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return [false, ['uses' => 'someController'], ['token' => 'foo.bar.baz']];
        });

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            new LumenRouteParams,
        ]);

        $this->assertSame($parser->parseToken(), 'foo.bar.baz');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_null_if_no_token_in_request()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return $this->getRouteMock();
        });

        $parser = new Parser($request);
        $parser->setChain([
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_retrieve_the_chain()
    {
        $chain = [
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ];

        $parser = new Parser(Mockery::mock(Request::class));
        $parser->setChain($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_retrieve_the_chain_with_alias()
    {
        $chain = [
            'header' => new AuthHeaders,
            'query' => new QueryString,
            'input' => new InputSource,
            'route' => new RouteParams,
        ];

        /* @var \Illuminate\Http\Request $request */
        $request = Mockery::mock(Request::class);

        $parser = new Parser($request);
        $parser->setChainOrder($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_set_the_cookie_key()
    {
        $cookies = (new Cookies)->setKey('test');
        $this->assertInstanceOf(Cookies::class, $cookies);
    }

    protected function getRouteMock($expectedParameterValue = null, $expectedParameterName = 'token')
    {
        return Mockery::mock(Route::class)
            ->shouldReceive('parameter')
            ->with($expectedParameterName)
            ->andReturn($expectedParameterValue)
            ->getMock();
    }
}
