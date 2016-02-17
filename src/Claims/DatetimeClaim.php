<?php

namespace Tymon\JWTAuth\Claims;

use DateTimeInterface;

abstract class DatetimeClaim extends Claim
{
    /**
     * {@inheritdoc}
     */
    public function setValue($value)
    {
        if ($value instanceof DateTimeInterface) {
            $value = $value->getTimestamp();
        }

        return parent::setValue($value);
    }
}