<?php

namespace Namshi\JOSE;

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
        $this->payload = $payload;
        $this->header  = $header;
    }

    /**
     * Generates the signininput for the current JWT.
     *
     * @return string
     */
    public function generateSigninInput()
    {
        $base64payload  = self::encodeBase64Url(json_encode($this->getPayload()));
        $base64header   = self::encodeBase64Url(json_encode($this->getHeader()));

        return sprintf("%s.%s", $base64header, $base64payload);
    }

    protected static function encodeBase64Url($data)
    {
        return strtr(rtrim(base64_encode($data), '='), '+/', '-_');
    }

    protected static function decodeBase64Url($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
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
}
