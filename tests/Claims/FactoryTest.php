<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Validators;

use Tymon\JWTAuth\Claims\Factory;

class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Tymon\JWTAuth\Claims\Factory
     */
    protected $factory;

    public function setUp()
    {
        $this->factory = new Factory;
    }

    /** @test */
    public function it_should_get_a_defined_claim_instance_when_passing_a_name_and_value()
    {
        $this->assertInstanceOf(\Tymon\JWTAuth\Claims\Subject::class, $this->factory->get('sub', 1));
    }

    /** @test */
    public function it_should_get_a_custom_claim_instance_when_passing_a_non_defined_name_and_value()
    {
        $this->assertInstanceOf(\Tymon\JWTAuth\Claims\Custom::class, $this->factory->get('foo', ['bar']));
    }
}
