<?php

namespace Tymon\JWTAuth\Claims;

interface ClaimInterface
{
    /**
     * Set the claim value, and call a validate method if available
     *
     * @param mixed
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
     * @param string  $name
     */
    public function setName($name);

    /**
     * Get the claim name
     *
     * @return string
     */
    public function getName();
}