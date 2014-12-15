<?php

namespace Tymon\JWTAuth\Claims;

abstract class Claim implements ClaimInterface
{

    /**
     * The claim type
     *
     * @var string
     */
    protected $type;

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
     * @param string  $type
     */
    public function __construct($value, $type = null)
    {
        $this->setValue($value);
        if (! is_null($type)) {
            $this->setType($type);
        }
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
     * Set the claim type
     *
     * @param string  $type
     */
    public function setType($type)
    {
        $this->type = $type;

        return $this;
    }

    /**
     * Get the claim type
     *
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Set whether the claim is required
     *
     * @param boolean  $required
     */
    public function setRequired($required)
    {
        $this->required = $required;

        return $this;
    }

    /**
     * Determine whether the claim is required
     *
     * @return boolean
     */
    public function isRequired()
    {
        return $this->required;
    }

    /**
     * Build a key value array comprising of the claim type and value
     *
     * @return array
     */
    public function toArray()
    {
        return [$this->getType() => $this->getValue()];
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