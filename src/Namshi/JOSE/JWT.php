<?php

namespace Namshi\JOSE;

use Namshi\JOSE\Encoder\Base64UrlSafeEncoder;
use Namshi\JOSE\Encoder\JsonEncoder;
use Namshi\JOSE\Encoder\Encoder;

/**
 * Class representing a JSON Web Token.
 */
class JWT
{
    /**
     * @var array
     */
    protected $payload;

    /**
     * @var array
     */
    protected $header;

    /**
     * @var Encoder
     */
    protected $base64Encoder;

    /**
     * @var Encoder
     */
    protected $jsonEncoder;

    /**
     * Constructor.
     *
     * @param array $payload
     * @param array $header
     */
    public function __construct(array $payload, array $header)
    {
        $this->setPayload($payload);
        $this->setHeader($header);
        $this->setBase64Encoder(new Base64UrlSafeEncoder());
        $this->setJsonEncoder(new JsonEncoder());
    }

    /**
     * @param Encoder $encoder
     */
    public function setBase64Encoder(Encoder $encoder)
    {
        $this->base64Encoder = $encoder;

        return $this;
    }

    /**
     * @param Encoder $encoder
     * @deprecated Use setBase64Encoder()
     */
    public function setEncoder(Encoder $encoder)
    {
        return $this->setBase64Encoder($encoder);
    }

    /**
     * @param Encoder $encoder
     */
    public function setJsonEncoder(Encoder $encoder)
    {
        $this->jsonEncoder = $encoder;

        return $this;
    }

    /**
     * Generates the signininput for the current JWT.
     *
     * @return string
     */
    public function generateSigninInput()
    {
        $payload = $this->jsonEncoder->encode($this->getPayload());
        $base64payload = $this->base64Encoder->encode($payload);
        $header = $this->jsonEncoder->encode($this->getHeader());
        $base64header = $this->base64Encoder->encode($header);

        return sprintf('%s.%s', $base64header, $base64payload);
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

        return $this;
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

        return $this;
    }
}
