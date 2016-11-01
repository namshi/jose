<?php

namespace Namshi\JOSE;

use InvalidArgumentException;
use Namshi\JOSE\Base64\Base64Encoder;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\Base64\Encoder;
use Namshi\JOSE\Signer\SignerInterface;

/**
 * Class representing a JSON Web Signature.
 */
class JWS extends JWT
{
    protected $signature;
    protected $isSigned = false;
    protected $originalToken;
    protected $encodedSignature;
    protected $encryptionEngine;
    protected $supportedEncryptionEngines = array('OpenSSL', 'SecLib');

    /**
     * Constructor.
     *
     * @param array $header An associative array of headers. The value can be any type accepted by json_encode or a JSON serializable object
     *
     * @see http://php.net/manual/en/function.json-encode.php
     * @see http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
     *
     * @param string $encryptionEngine
     *                                 }
     */
    public function __construct($header = array(), $encryptionEngine = 'OpenSSL')
    {
        if (!in_array($encryptionEngine, $this->supportedEncryptionEngines)) {
            throw new InvalidArgumentException(sprintf('Encryption engine %s is not supported', $encryptionEngine));
        }

        if ('SecLib' === $encryptionEngine && version_compare(PHP_VERSION, '7.0.0-dev') >= 0) {
            throw new InvalidArgumentException("phpseclib 1.0.0(LTS), even the latest 2.0.0, doesn't support PHP7 yet");
        }

        $this->encryptionEngine = $encryptionEngine;

        parent::__construct(array(), $header);
    }

    /**
     * Signs the JWS signininput.
     *
     * @param resource|string $key
     * @param optional string $password
     *
     * @return string
     */
    public function sign($key, $password = null)
    {
        $this->signature = $this->getSigner()->sign($this->generateSigninInput(), $key, $password);
        $this->isSigned = true;

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

        return;
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

        return sprintf('%s.%s', $signinInput, $this->encoder->encode($this->getSignature()));
    }

    /**
     * Creates an instance of a JWS from a JWT.
     *
     * @param string  $jwsTokenString
     * @param bool    $allowUnsecure
     * @param Encoder $encoder
     * @param string  $encryptionEngine
     *
     * @return JWS
     *
     * @throws \InvalidArgumentException
     */
    public static function load($jwsTokenString, $allowUnsecure = false, Encoder $encoder = null, $encryptionEngine = 'OpenSSL')
    {
        if ($encoder === null) {
            $encoder = strpbrk($jwsTokenString, '+/=') ? new Base64Encoder() : new Base64UrlSafeEncoder();
        }

        $parts = explode('.', $jwsTokenString);

        if (count($parts) === 3) {
            $header = json_decode($encoder->decode($parts[0]), true);
            $payload = json_decode($encoder->decode($parts[1]), true);

            if (is_array($header) && is_array($payload)) {
                if (strtolower($header['alg']) === 'none' && !$allowUnsecure) {
                    throw new InvalidArgumentException(sprintf('The token "%s" cannot be validated in a secure context, as it uses the unallowed "none" algorithm', $jwsTokenString));
                }

                $jws = new static($header, $encryptionEngine);

                $jws->setEncoder($encoder)
                    ->setHeader($header)
                    ->setPayload($payload)
                    ->setOriginalToken($jwsTokenString)
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
     * @param string          $algo The algorithms this JWS should be signed with. Use it if you want to restrict which algorithms you want to allow to be validated.
     *
     * @return bool
     */
    public function verify($key, $algo = null)
    {
        if (empty($key) || ($algo && $this->header['alg'] !== $algo)) {
            return false;
        }

        $decodedSignature = $this->encoder->decode($this->getEncodedSignature());
        $signinInput = $this->getSigninInput();

        return $this->getSigner()->verify($key, $decodedSignature, $signinInput);
    }

    /**
     * Get the original token signin input if it exists, otherwise generate the
     * signin input for the current JWS
     *
     * @return string
     */
    private function getSigninInput()
    {
        $parts = explode('.', $this->originalToken);

        if (count($parts) >= 2) {
            return sprintf('%s.%s', $parts[0], $parts[1]);
        }

        return $this->generateSigninInput();
    }

    /**
     * Sets the original base64 encoded token.
     *
     * @param string $originalToken
     *
     * @return JWS
     */
    private function setOriginalToken($originalToken)
    {
        $this->originalToken = $originalToken;

        return $this;
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
     *
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
     *
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
