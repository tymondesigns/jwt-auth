<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Mockery;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

abstract class AbstractTestCase extends TestCase
{
    /**
     * @var int
     */
    protected $testNowTimestamp;

    /**
     * @var \Carbon\CarbonImmutable
     */
    protected $testNowTimestampInstance;

    public function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow($now = Carbon::now());
        $this->testNowTimestamp = $now->getTimestamp();
        $this->testNowTimestampInstance = CarbonImmutable::instance($now);
    }

    public function tearDown(): void
    {
        Carbon::setTestNow();
        Mockery::close();

        parent::tearDown();
    }
}
