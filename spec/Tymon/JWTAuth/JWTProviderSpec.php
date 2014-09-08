<?php namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Illuminate\Http\Request;
use Mockery;

class JWTProviderSpec extends ObjectBehavior
{

    function it_is_initializable()
    {
    	$request = Mockery::mock('Illuminate\Http\Request');
    	$this->beConstructedWith('secret', $request);

        $this->shouldHaveType('Tymon\JWTAuth\JWTProvider');
    }

    function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
    	$request = Mockery::mock('Illuminate\Http\Request');
		$request->shouldReceive('url')->once()->andReturn('http://example.com');
    	$this->beConstructedWith('secret', $request);

    	$token = $this->encode(1);

    	$token->shouldHaveType('Tymon\JWTAuth\JWT');
    	$token->get()->shouldBeString();
    }

    function it_should_throw_an_exception_when_not_passing_a_subject_to_encode()
    {
        $request = Mockery::mock('Illuminate\Http\Request');
        $request->shouldReceive('url')->once()->andReturn('http://example.com');
        $this->beConstructedWith('secret', $request);

        $this->shouldThrow('Tymon\JWTAuth\Exceptions\JWTException')->during('encode', []);
    }

    // function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    // {
    //     $request = Mockery::mock('Illuminate\Http\Request');
    //     $request->shouldReceive('url')->once()->andReturn('http://example.com');
    //     $this->beConstructedWith('secret', $request);

    //     $payload = $this->decode();

    //     $payload->shouldHaveType('Tymon\JWTAuth\JWTPayload');
    //     $payload->get()->shouldBeArray();
    // }

    function it_should_throw_an_exception_when_not_passing_a_token_to_decode()
    {
        $request = Mockery::mock('Illuminate\Http\Request');
        $request->shouldReceive('url')->once()->andReturn('http://example.com');
        $this->beConstructedWith('secret', $request);

        $this->shouldThrow('Tymon\JWTAuth\Exceptions\JWTException')->during('decode', []);
    }

}

class TokenStub {
    public static function encode() {

    }
}
