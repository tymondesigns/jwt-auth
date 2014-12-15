<?php

namespace Tymon\JWTAuth\Claims;

class Issuer extends Claim
{
	/**
     * The claim type
     *
     * @var string
     */
	protected $type = 'iss';

	/**
     * Whether the claim is required
     *
     * @var boolean
     */
	protected $required = true;
}