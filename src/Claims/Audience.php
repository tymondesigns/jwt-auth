<?php

namespace Tymon\JWTAuth\Claims;

class Audience extends Claim
{
	/**
     * The claim type
     *
     * @var string
     */
	protected $type = 'aud';
}