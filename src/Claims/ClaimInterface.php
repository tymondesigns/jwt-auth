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
     * Set the claim type
     *
     * @param string  $type
     */
    public function setType($type);

    /**
     * Get the claim type
     *
     * @return string
     */
    public function getType();

    /**
     * Set whether the claim is required
     *
     * @param boolean  $required
     */
    public function setRequired($required);

    /**
     * Determine whether the claim is required
     *
     * @return boolean
     */
    public function isRequired();
}