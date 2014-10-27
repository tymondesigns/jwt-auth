<?php namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Providers\FirebaseAdapter;
use Tymon\JWTAuth\Auth\IlluminateAuthAdapter;

class JWTAuthSpec extends ObjectBehavior
{

	function let(FirebaseAdapter $provider, Model $user, IlluminateAuthAdapter $auth, Request $request)
	{
    	$this->beConstructedWith($user, $provider, $auth, $request);
	}

    function it_is_initializable()
    {
        $this->shouldHaveType('Tymon\JWTAuth\JWTAuth');
    }

    // function it_should_return_a_user_when_passing_a_user()
    // {

    // }

    // function it_should_get_the_token_from_the_request_when_passing_via_query_string(Request $request)
    // {
    //     $request->header->get('authorization')->willReturn('foo');
    //     $request->query('token')->willReturn('foo.bar.baz');
    //     $token = $this->getToken();
    // }

    // function it_should_generate_token_when_passing_a_user_object(Model $user)
    // {
    // 	$user->id->willReturn(1);
    // 	$token = $this->fromUser($user);
    // }
}