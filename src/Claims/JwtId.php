<?php

namespace Tymon\JWTAuth\Claims;

class Issuer extends Claim
{
	/**
     * The claim type
     *
     * @var string
     */
	protected $type = 'jti';

	/**
     * Whether the claim is required
     *
     * @var boolean
     */
	protected $required = true;
}