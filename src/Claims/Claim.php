<?php

namespace Tymon\JWTAuth\Claims;

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
     * Whether the claim is required
     *
     * @var boolean
     */
    protected $required = false;

    /**
     * @param mixed   $value
     */
    public function __construct($value)
    {
        $this->setValue($value);
    }

    /**
     * Set the claim value, and call a validate method if available
     *
     * @param mixed
     */
    public function setValue($value)
    {
        if (method_exists($this, 'validate')) {
            if (! $this->validate($value)) {
                throw new \Exception('Invalid value provided for claim "' . $this->getType() . '": ' . $value);
            }
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