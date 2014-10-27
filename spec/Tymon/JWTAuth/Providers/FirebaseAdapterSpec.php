<?php namespace spec\Tymon\JWTAuth\Providers;

use PhpSpec\ObjectBehavior;
use Illuminate\Http\Request;

class FirebaseAdapterSpec extends ObjectBehavior
{

    function let(Request $request)
    {
        $request->url()->willReturn('http://example.com');
        $this->beConstructedWith('secret', $request);
    }

    function it_is_initializable(Request $request)
    {
        $this->shouldHaveType('Tymon\JWTAuth\Providers\FirebaseAdapter');
    }

    function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
    	$token = $this->encode(1);

    	$token->shouldHaveType('Tymon\JWTAuth\Token');
    	$token->get()->shouldBeString();
    }

    function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $token = $this->encode(1)->get();
        $payload = $this->decode($token);

        $payload->shouldHaveType('Tymon\JWTAuth\Payload');
        $payload['sub']->shouldBe(1);
        $payload->get('sub')->shouldBe(1);
    }
}
