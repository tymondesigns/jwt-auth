<?php

namespace Tymon\JWTAuth\Test\Providers\JWT;

use Tymon\JWTAuth\Providers\JWT\FirebaseAdapter;
use Tymon\JWTAuth\Payload;
use Tymon\JWTAuth\PayloadFactory;

use Tymon\JWTAuth\Claims\Issuer;
use Tymon\JWTAuth\Claims\IssuedAt;
use Tymon\JWTAuth\Claims\Expiration;
use Tymon\JWTAuth\Claims\NotBefore;
use Tymon\JWTAuth\Claims\Audience;
use Tymon\JWTAuth\Claims\Subject;
use Tymon\JWTAuth\Claims\JwtId;
use Tymon\JWTAuth\Claims\Custom;

class PayloadTest extends \PHPUnit_Framework_TestCase
{

    public function setUp()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration(time() + 3600),
            new IssuedAt(time()),
            new JwtId('foo')
        ];

        $this->payload = new Payload($claims);

        $this->payload->setProvider(new FirebaseAdapter('secret'));
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_add_to_the_payload()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\PayloadException');

        $this->payload['foo'] = 'bar';
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_remove_a_key_from_the_payload()
    {
        $this->setExpectedException('Tymon\JWTAuth\Exceptions\PayloadException');

        unset($this->payload['foo']);
    }

    /** @test */
    public function it_should_cast_the_payload_to_a_string_as_json()
    {
        $this->assertEquals((string) $this->payload, json_encode($this->payload->get()));
        $this->assertJsonStringEqualsJsonString((string) $this->payload, json_encode($this->payload->get()));
    }

    /** @test */
    public function it_should_allow_array_access_on_the_payload()
    {
        $this->assertTrue(isset($this->payload['iat']));
        $this->assertEquals($this->payload['sub'], 1);
        $this->assertArrayHasKey('exp', $this->payload);
    }

    /** @test */
    public function it_should_get_properties_of_payload_via_get_method()
    {
        $this->assertInternalType('array', $this->payload->get());
        $this->assertEquals($this->payload->get('sub'), 1);
    }

    /** @test */
    public function it_should_get_multiple_properties_when_passing_an_array_to_the_get_method()
    {
        $values = $this->payload->get(['sub', 'jti']);

        list($sub, $jti) = $values;

        $this->assertInternalType('array', $values);
        $this->assertEquals($sub, 1);
        $this->assertEquals($jti, 'foo');
    }

    /** @test */
    public function it_should_return_token_instance_when_calling_token_method()
    {
        // $this->encode()
        $token = $this->payload->token();
        $this->assertInstanceOf('Tymon\JWTAuth\Token', $token);
    }

    /** @test */
    public function it_should_determine_whether_the_payload_has_a_claim()
    {
        $this->assertTrue($this->payload->has(new Subject(1)));
        $this->assertFalse($this->payload->has(new Audience(1)));
    }

}