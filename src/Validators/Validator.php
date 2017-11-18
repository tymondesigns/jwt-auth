<?php declare(strict_types=1);

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Validators;

use Tymon\JWTAuth\Contracts\Validator as ValidatorContract;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Support\RefreshFlow;

abstract class Validator implements ValidatorContract
{
    use RefreshFlow;

    /**
     * Helper function to return a boolean.
     */
    public function isValid(array $value): bool
    {
        try {
            $this->check($value);
        } catch (JWTException $e) {
            return false;
        }

        return true;
    }

    /**
     * Run the validation.
     *
     * @param  array  $value
     *
     * @return mixed
     */
    abstract public function check($value);
}
