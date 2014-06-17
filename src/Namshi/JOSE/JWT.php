<?php

namespace Namshi\JOSE;

use Namshi\JOSE\Base64;

/**
 * Class representing a JSON Web Token.
 */
class JWT
{
    protected $payload;
    protected $header;

    /**
     * Constructor
     *
     * @param array $payload
     * @param array $header
     */
    public function __construct(array $payload, array $header)
    {
        $this->setPayload($payload);
        $this->setHeader($header);
    }

    /**
     * Generates the signininput for the current JWT.
     *
     * @return string
     */
    public function generateSigninInput()
    {
        $base64header   = Base64::encode(json_encode($this->getHeader()));
        $base64payload  = Base64::encode(json_encode($this->getPayload()));

        return sprintf("%s.%s", $base64header, $base64payload);
    }

    /**
     * Returns the payload of the JWT.
     *
     * @return array
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * Sets the payload of the current JWT.
     *
     * @param array $payload
     */
    public function setPayload(array $payload)
    {
        $this->payload = $payload;

        if (!isset($this->payload['iat'])) {
            $now                    = new \DateTime('now');
            $this->payload['iat']   = $now->format('U');
        }
    }

    /**
     * Returns the header of the JWT.
     *
     * @return array
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Sets the header of this JWT.
     *
     * @param array $header
     */
    public function setHeader(array $header)
    {
        $this->header = $header;
    }

    /**
     * Checks whether the token is expired.
     *
     * @return bool
     */
    protected function isExpired()
    {
        $payload = $this->getPayload();

        if (isset($payload['exp']) && is_numeric($payload['exp'])) {
            $now            = new \DateTime('now');

            return ($now->format('U') - $payload['exp']) > 0;
        }

        return false;
    }
}
