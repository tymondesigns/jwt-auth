<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Mockery;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Providers\JWT\FirebaseAdapter;

class FirebaseAdapterTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->jwt = new FirebaseAdapter('secret', Request::create('/foo', 'GET'));
        $this->firebase = Mockery::mock('alias:Firebase');
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_subject_to_encode()
    {
        $token = $this->jwt->encode(1);

        $this->assertInstanceOf('Tymon\JWTAuth\Token', $token);
        $this->assertInternalType('string', $token->get());
        // $this->assertEquals(count(explode('.', $token)), 3);
    }

    /** @test */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $token = $this->jwt->encode(1)->get();
        $payload = $this->jwt->decode($token);

        $this->assertInstanceOf('Tymon\JWTAuth\Payload', $payload);
        $this->assertInternalType('array', $payload->get());
        $this->assertEquals($payload['sub'], 1);
        $this->assertEquals($payload->get('sub'), 1);
        $this->assertTrue(isset($payload['iat']));
    }

}
