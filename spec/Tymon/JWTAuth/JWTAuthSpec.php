<?php namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Providers\FirebaseProvider;

class JWTAuthSpec extends ObjectBehavior
{

	function let(FirebaseProvider $provider, Model $user, AuthManager $auth, Request $request)
	{
    	$this->beConstructedWith($user, $provider, $auth, $request);
	}

    function it_is_initializable()
    {
        $this->shouldHaveType('Tymon\JWTAuth\JWTAuth');
    }

    // function it_should_generate_token_when_passing_a_user_object(Model $user)
    // {
    // 	$user->id->willReturn(1);
    // 	$token = $this->fromUser($user);
    // }
}