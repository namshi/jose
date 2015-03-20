<?php

namespace Namshi\JOSE;

use InvalidArgumentException;
use Namshi\JOSE\Base64\Base64Encoder;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\Signer\SignerInterface;
use Namshi\JOSE\Base64\Encoder;

/**
 * Class representing a JSOn Web Signature.
 */
class JWS extends JWT
{
    protected $signature;
    protected $isSigned = false;
    protected $encodedSignature;
    protected $encryptionEngine;

    /**
     * Constructor
     *
     * @param string $algorithm
     * @param string $type
     * @param string $encryptionEngine
     */
    public function __construct($algorithm, $type = null, $encryptionEngine = "OpenSSL")
    {
        if ($encryptionEngine != "OpenSSL" and $encryptionEngine != "SecLib") {
            throw new InvalidArgumentException(sprintf("Encryption engine %s is unsupported", $encryptionEngine));
        }
        $this->encryptionEngine = $encryptionEngine;
        parent::__construct(array(), array('alg' => $algorithm, 'typ' => $type ?: "JWS"));
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
                if ($header['alg'] === 'None' && !$allowUnsecure) {
                    throw new InvalidArgumentException(sprintf('The token "%s" cannot be validated in a secure context, as it uses the unallowed "none" algorithm', $jwsTokenString));
                }

                $jws = new self($header['alg'], isset($header['typ']) ? $header['typ'] : null, $encryptionEngine);
                
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
     * Checks that the JWS has been signed with a valid private key by verifying it with a public $key
     * and the token is not expired.
     *
     * @param resource|string $key
     * @param string $algo The algorithms this JWS should be signed with. Use it if you want to restrict which algorithms you want to allow to be validated.
     * 
     * @return bool
     */
    public function isValid($key, $algo = null)
    {
        return $this->verify($key, $algo) && ! $this->isExpired();
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
        $signerClass = sprintf("Namshi\\JOSE\\Signer\\$this->encryptionEngine\\%s", $this->header['alg']);

        if (class_exists($signerClass)) {
            return new $signerClass();
        }

        throw new InvalidArgumentException(
            sprintf("The algorithm '%s' is not supported for %s", $this->header['alg'], $this->encryptionEngine));
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
            $now = new \DateTime('now');

            return ($now->format('U') - $payload['exp']) > 0;
        }

        return false;
    }
}
