<?php namespace spec\Tymon\JWTAuth\Providers;

use PhpSpec\ObjectBehavior;
use Illuminate\Http\Request;
use Mockery;

class FirebaseProviderSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $request = Mockery::mock('Illuminate\Http\Request');
    	$this->beConstructedWith('secret', $request);

        $this->shouldHaveType('Tymon\JWTAuth\Providers\FirebaseProvider');
    }

    function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
    	$request = Mockery::mock('Illuminate\Http\Request');
		$request->shouldReceive('url')->once()->andReturn('http://example.com');
    	$this->beConstructedWith('secret', $request);

    	$token = $this->encode(1);

    	$token->shouldHaveType('Tymon\JWTAuth\Token');
    	$token->get()->shouldBeString();
    }

    function it_should_throw_an_exception_when_not_passing_a_subject_to_encode()
    {
        $request = Mockery::mock('Illuminate\Http\Request');
        $request->shouldReceive('url')->once()->andReturn('http://example.com');
        $this->beConstructedWith('secret', $request);

        $this->shouldThrow('Tymon\JWTAuth\Exceptions\JWTException')->during('encode', []);
    }

    function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $request = Mockery::mock('Illuminate\Http\Request');
        $request->shouldReceive('url')->once()->andReturn('http://example.com');
        $this->beConstructedWith('secret', $request);

        $token = $this->encode(1)->get();
        $payload = $this->decode($token);

        $payload->shouldHaveType('Tymon\JWTAuth\Payload');
        $payload['sub']->shouldBe(1);
        $payload->get('sub')->shouldBe(1);
    }

    function it_should_throw_an_exception_when_not_passing_a_token_to_decode()
    {
        $request = Mockery::mock('Illuminate\Http\Request');
        $request->shouldReceive('url')->once()->andReturn('http://example.com');
        $this->beConstructedWith('secret', $request);

        $this->shouldThrow('Tymon\JWTAuth\Exceptions\JWTException')->during('decode', []);
    }
}
