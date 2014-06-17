<?php

namespace Namshi\JOSE;

use InvalidArgumentException;
use Namshi\JOSE\Base64;

/**
 * Class representing a JSOn Web Signature.
 */
class JWS extends JWT
{
    protected $signature;
    protected $isSigned = false;
    protected $encodedSignature;

    /**
     * Constructor
     *
     * @param array $algorithm
     * @param array $type
     */
    public function __construct($algorithm, $type = null)
    {
        parent::__construct(
            array(),
            array(
                'alg' => $algorithm,
                'typ' => $type ?: "JWS"
            )
        );
    }

    /**
     * Signs the JWS signininput.
     *
     * @param  resource $key
     * @return string
     */
    public function sign($key)
    {
        $this->signature    = $this->getSigner()->sign($this->generateSigninInput(), $key);
        $this->isSigned     = true;

        return $this->signature;
    }

    /**
     * Returns the signature representation of the JWS.
     *
     * @return string
     */
    public function getSignature()
    {
        if ($this->isSigned()) {
            return $this->signature;
        }

        return null;
    }

    /**
     * Checks whether the JSW has already been signed.
     *
     * @return bool
     */
    public function isSigned()
    {
        return (bool) $this->isSigned;
    }

    /**
     * Returns the string representing the JWT.
     *
     * @return string
     */
    public function getTokenString()
    {
        $signinInput = parent::generateSigninInput();

        return sprintf("%s.%s", $signinInput, Base64::encode($this->getSignature()));
    }

    /**
     * Creates an instance of a JWS from a JWT.
     *
     * @param  string          $jwsTokenString
     * @return Namshi\JOSE\JWS
     */
    public static function load($jwsTokenString)
    {
        $parts = explode('.', $jwsTokenString);

        if (count($parts) === 3) {
            $header     = json_decode(Base64::decode($parts[0]), true);
            $payload    = json_decode(Base64::decode($parts[1]), true);

            if (is_array($header) && is_array($payload)) {
                $jws        = new self($header['alg'], isset($header['type']) ? $header['type'] : null);
                $jws->setPayload($payload);
                $jws->setEncodedSignature($parts[2]);

                return $jws;
            }
        }

        throw new InvalidArgumentException(sprintf('The token "%s" is an invalid JWS', $jwsTokenString));
    }

    /**
     * Verifies that the internal signininput corresponds to the encoded
     * signature previously stored (@see JWS::load).
     *
     * @param  string $key
     * @return bool
     */
    public function verify($key)
    {
        $decodedSignature   = Base64::decode($this->getEncodedSignature());
        $signinInput        = $this->generateSigninInput();

        return $this->getSigner()->verify($key, $decodedSignature, $signinInput);
    }

    /**
     * Checks that the JWS has been signed with a valid private key by verifying it with a public $key
     * and the token is not expired.
     *
     * @param $key
     *
     * @return bool
     */
    public function isValid($key)
    {
        return $this->verify($key) && !$this->isExpired();
    }

    /**
     * Returns the base64 encoded signature.
     *
     * @return string
     */
    public function getEncodedSignature()
    {
        return $this->encodedSignature;
    }

    /**
     * Sets the base64 encoded signature.
     *
     * @param string $encodedSignature
     */
    public function setEncodedSignature($encodedSignature)
    {
        $this->encodedSignature = $encodedSignature;
    }

    /**
     * Returns the signer responsible to encrypting / decrypting this JWS.
     *
     * @return \Namshi\JOSE\Signer\SignerInterface
     */
    protected function getSigner()
    {
        $signerClass = sprintf("Namshi\\JOSE\\Signer\\%s", $this->header['alg']);

        if (class_exists($signerClass)) {
            return new $signerClass();
        }

        throw new InvalidArgumentException(sprintf("The algorithm '%s' is not supported", $this->header['alg']));
    }
}
