<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Validators\TokenValidator;

final class Token
{

    /**
     * @var string
     */
    private $value;

    /**
     * Create a new JSON Web Token
     *
     * @param string  $value
     */
    public function __construct($value)
    {
        with(new TokenValidator)->check($value);

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
     * Get the decoded payload for the token
     *
     * @return \Tymon\JWTAuth\Payload
     */
    public function payload()
    {
        // decode $this->value and return \Tymon\JWTAuth\Payload instance
    }

    /**
     * Get the token when casting to string
     *
     * @return string
     */
    public function __toString()
    {
        return (string) $this->value;
    }
}
