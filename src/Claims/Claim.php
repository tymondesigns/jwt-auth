<?php

namespace Tymon\JWTAuth\Claims;

use Tymon\JWTAuth\Exceptions\InvalidClaimException;

abstract class Claim implements ClaimInterface
{

    /**
     * The claim name
     *
     * @var string
     */
    protected $name;

    /**
     * The claim value
     *
     * @var mixed
     */
    private $value;

    /**
     * @param mixed   $value
     * @param string $name
     */
    public function __construct($value, $name = null)
    {
        $this->setValue($value);
        if (! is_null($name)) {
            $this->setName($name);
        }
    }

    /**
     * Set the claim value, and call a validate method if available
     *
     * @param mixed
     */
    public function setValue($value)
    {
        if (! $this->validate($value)) {
            throw new InvalidClaimException('Invalid value provided for claim "' . $this->getName() . '": ' . $value);
        }

        $this->value = $value;

        return $this;
    }

    /**
     * Get the claim value
     *
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Set the claim name
     *
     * @param string  $name
     */
    public function setName($name)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get the claim name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Default validate call
     *
     * @return boolean
     */
    protected function validate($value)
    {
        return true;
    }

    /**
     * Build a key value array comprising of the claim name and value
     *
     * @return array
     */
    public function toArray()
    {
        return [$this->getName() => $this->getValue()];
    }

    /**
     * Get the claim as a string
     *
     * @return string
     */
    public function __toString()
    {
        return json_encode($this->toArray());
    }
}
