<?php

namespace Tymon\JWTAuth\Claims;

class Subject extends Claim
{
    /**
     * The claim type
     *
     * @var string
     */
    protected $type = 'sub';

    /**
     * Whether the claim is required
     *
     * @var boolean
     */
    protected $required = true;
}