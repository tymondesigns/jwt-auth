<?php

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Validators\TokenValidator;
use Tymon\JWTAuth\Driver;
use Tymon\JWTAuth\Payload;

class Token
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
     * Refresh the token
     *
     * @return \Tymon\JWTAuth\Token
     */
    public function refresh()
    {
        return $this->payload()->setRefreshFlow()->token();
    }

    /**
     * Invalidate the token
     *
     * @return boolean
     */
    public function invalidate()
    {
        $this->blacklist->add($this->payload());
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
