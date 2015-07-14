<?php

namespace Tymon\JWTAuth\Test\Validators;

use Mockery;
use Tymon\JWTAuth\Claims\Factory;

class FactoryTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->factory = new Factory;
    }

    /** @test */
    public function it_should_get_a_defined_claim_instance_when_passing_a_name_and_value()
    {
        $this->assertInstanceOf('Tymon\JWTAuth\Claims\Subject', $this->factory->get('sub', 1));
    }

    /** @test */
    public function it_should_get_a_custom_claim_instance_when_passing_a_non_defined_name_and_value()
    {
        $this->assertInstanceOf('Tymon\JWTAuth\Claims\Custom', $this->factory->get('foo', ['bar']));
    }
}
