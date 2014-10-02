<?php namespace spec\Tymon\JWTAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Tymon\JWTAuth\Providers\FirebaseProvider;
use Mockery;

class JWTAuthSpec extends ObjectBehavior
{

	function let(FirebaseProvider $provider)
	{
		$auth = Mockery::mock('Illuminate\Auth\AuthManager');
        $request = Mockery::mock('Illuminate\Http\Request');
    	$this->beConstructedWith($provider, $auth, $request);
	}

    function it_is_initializable()
    {
        $this->shouldHaveType('Tymon\JWTAuth\JWTAuth');
    }

    // function it_should_generate_token_when_passing_a_user_object(User $user)
    // {
    // 	$user->id->shouldReturn(1);
    // 	$token = $this->fromUser($user);
    // }
}

class User {}