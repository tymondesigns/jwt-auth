<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Validators\TokenValidator;

class Token
{

    /**
     * @var string
     */
    protected $value;

    /**
     * Create a new JSON Web Token
     *
     * @param string $value
     */
    public function __construct($value)
    {
        TokenValidator::check($value);

        $this->value = $value;
    }

    /**
     * Get the token
     *
     * @return string
     */
    public function get()
    {
        return $this->value;
    }

    /**
     * Get the token when casting to string
     *
     * @return string
     */
    public function __toString()
    {
        return $this->value;
    }
}
