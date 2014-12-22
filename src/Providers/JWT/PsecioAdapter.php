<?php

namespace Tymon\JWTAuth\Providers\JWT;

use Exception;
use Psecio\Jwt\Jwt;
use Psecio\Jwt\Header;
use Tymon\JWTAuth\Exceptions\JWTException;

class PsecioAdapter extends JWTProvider implements JWTInterface
{
    /**
     * Create a JSON Web Token
     *
     * @return string
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function encode(array $payload)
    {
        try {
            return with(new Jwt($this->getHeader()))->encode($payload);
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage());
        }
    }

    /**
     * Decode a JSON Web Token
     *
     * @param  string  $token
     * @return array
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     */
    public function decode($token)
    {
        try {
            return with(new Jwt($this->getHeader()))->decode($token);
        } catch (Exception $e) {
            if (get_class($e) === 'Psecio\Jwt\Exception\BadSignatureException') {
                throw new JWTException('Could not decode token: ' . $e->getMessage());
            }
        }
    }

    /**
     * Get the JWT Header instance
     *
     * @return \Psecio\Jwt\Header
     */
    protected function getHeader()
    {
        return with(new Header($this->secret))->setAlgorithm($this->algo);
    }
}
