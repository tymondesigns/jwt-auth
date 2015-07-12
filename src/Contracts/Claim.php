<?php

namespace Tymon\JWTAuth\Contracts;

interface Claim
{
    /**
     * Set the claim value, and call a validate method
     *
     * @param mixed $value
     *
     * @throws \Tymon\JWTAuth\Exceptions\InvalidClaimException
     *
     * @return Claim
     */
    public function setValue($value);

    /**
     * Get the claim value
     *
     * @return mixed
     */
    public function getValue();

    /**
     * Set the claim name
     *
     * @param string $name
     *
     * @return Claim
     */
    public function setName($name);

    /**
     * Get the claim name
     *
     * @return string
     */
    public function getName();

    /**
     * Validate the Claim value
     *
     * @param  mixed $value
     *
     * @return boolean
     */
    public function validate($value);
}
