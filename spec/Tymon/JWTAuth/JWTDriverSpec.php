<?php namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Illuminate\Http\Request;
use Mockery;

class JWTDriverSpec extends ObjectBehavior
{

    function it_is_initializable()
    {
    	$request = Mockery::mock('Illuminate\Http\Request');
    	$this->beConstructedWith('secret', $request);

        $this->shouldHaveType('Tymon\JWTAuth\JWTDriver');
    }

    function it_should_return_the_token_for_a_subject()
    {
    	// Arrange
    	$request = Mockery::mock('Illuminate\Http\Request');
		$request->shouldReceive('url')->once()->andReturn('http://example.com');
    	$this->beConstructedWith('secret', $request);

    	// Act
    	$token = $this->encode(1);

    	// Assert
    	$token->shouldHaveType('Tymon\JWTAuth\JWT');
    	$token->get()->shouldBeString();
    }

}
