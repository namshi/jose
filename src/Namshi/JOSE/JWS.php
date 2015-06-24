<?php

namespace Namshi\JOSE;

use InvalidArgumentException;
use Namshi\JOSE\Base64\Base64Encoder;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\Signer\SignerInterface;
use Namshi\JOSE\Base64\Encoder;

/**
 * Class representing a JSON Web Signature.
 */
class JWS extends JWT
{
    protected $signature;
    protected $isSigned = false;
    protected $encodedSignature;
    protected $encryptionEngine;
    protected $supportedEncryptionEngines = array('OpenSSL', 'SecLib');

    /**
     * Constructor
     *
     * @param array $header An associative array of headers. The value can be any type accepted by json_encode or a JSON serializable object
     * @see http://php.net/manual/en/function.json-encode.php
     * @see http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
     * @param string $encryptionEngine
     * }
     */
    public function __construct($header = array(), $encryptionEngine = "OpenSSL")
    {
        if (!in_array($encryptionEngine, $this->supportedEncryptionEngines)) {
            throw new InvalidArgumentException(sprintf("Encryption engine %s is not supported", $encryptionEngine));
        }
        $this->encryptionEngine = $encryptionEngine;

        parent::__construct(array(), $header);
    }

    /**
     * Signs the JWS signininput.
     *
     * @param  resource $key
     * @param optional string $password
     * @return string
     */
    public function sign($key, $password = null)
    {
        $this->signature = $this->getSigner()->sign($this->generateSigninInput(), $key, $password);
        $this->isSigned  = true;

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
        $signinInput = $this->generateSigninInput();

        return sprintf("%s.%s", $signinInput, $this->encoder->encode($this->getSignature()));
    }

    /**
     * Creates an instance of a JWS from a JWT.
     *
     * @param string $jwsTokenString
     * @return JWS
     * @throws \InvalidArgumentException
     */
    public static function load($jwsTokenString, $allowUnsecure = false, Encoder $encoder = null, $encryptionEngine = 'OpenSSL')
    {
        if ($encoder === null) {
            $encoder = strpbrk($jwsTokenString, '+/=') ? new Base64Encoder() : new Base64UrlSafeEncoder();
        }
        
        $parts = explode('.', $jwsTokenString);

        if (count($parts) === 3) {
            $header  = json_decode($encoder->decode($parts[0]), true);
            $payload = json_decode($encoder->decode($parts[1]), true);

            if (is_array($header) && is_array($payload)) {
                if (strtolower($header['alg']) === 'none' && !$allowUnsecure) {
                    throw new InvalidArgumentException(sprintf('The token "%s" cannot be validated in a secure context, as it uses the unallowed "none" algorithm', $jwsTokenString));
                }

                $jws = new static($header, $encryptionEngine);

                $jws->setEncoder($encoder)
                    ->setHeader($header)
                    ->setPayload($payload)
                    ->setEncodedSignature($parts[2]);

                return $jws;
            }
        }

        throw new InvalidArgumentException(sprintf('The token "%s" is an invalid JWS', $jwsTokenString));
    }

    /**
     * Verifies that the internal signin input corresponds to the encoded
     * signature previously stored (@see JWS::load).
     *
     * @param resource|string $key
     * @param string $algo The algorithms this JWS should be signed with. Use it if you want to restrict which algorithms you want to allow to be validated.
     * @return bool
     */
    public function verify($key, $algo = null)
    {
        if (empty($key) || ($algo && $this->header['alg'] !== $algo)) {
            return false;
        }

        $decodedSignature = $this->encoder->decode($this->getEncodedSignature());
        $signinInput      = $this->generateSigninInput();

        return $this->getSigner()->verify($key, $decodedSignature, $signinInput);
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
     * @param  string $encodedSignature
     * @return JWS
     */
    public function setEncodedSignature($encodedSignature)
    {
        $this->encodedSignature = $encodedSignature;
        
        return $this;
    }

    /**
     * Returns the signer responsible to encrypting / decrypting this JWS.
     *
     * @return SignerInterface
     * @throws \InvalidArgumentException
     */
    protected function getSigner()
    {
        $signerClass = sprintf('Namshi\\JOSE\\Signer\\%s\\%s', $this->encryptionEngine, $this->header['alg']);

        if (class_exists($signerClass)) {
            return new $signerClass();
        }

        throw new InvalidArgumentException(
            sprintf("The algorithm '%s' is not supported for %s", $this->header['alg'], $this->encryptionEngine));
    }
}
