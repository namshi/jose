<?php

namespace Namshi\JOSE\Signer\OpenSSL;

use phpseclib\File\ASN1;

/**
 * Class responsible to sign inputs with the a ECDSA algorithm, after hashing it.
 */
abstract class ECDSA extends PublicKey
{
    public function __construct()
    {
        if (version_compare(PHP_VERSION, '7.0.0-dev') >= 0) {
            throw new \InvalidArgumentException("phpseclib 1.0.0(LTS), even the latest 2.0.0, doesn't support PHP7 yet");
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function supportsKey($key)
    {
        if (false === parent::supportsKey($key)) {
            return false;
        }

        // openssl_sign with EC keys was introduced in this PHP release
        $minVersions = array(
            '5.4' => '5.4.26',
            '5.5' => '5.5.10',
            '5.6' => '5.6.0',
        );

        if (isset($minVersions[PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION]) &&
            version_compare(PHP_VERSION, $minVersions[PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION], '<')) {
            return false;
        }

        $keyDetails = openssl_pkey_get_details($key);

        if (0 === preg_match('/-----BEGIN PUBLIC KEY-----([^-]+)-----END PUBLIC KEY-----/', $keyDetails['key'], $matches)) {
            return false;
        }
        $publicKey = trim($matches[1]);
        $asn1 = new ASN1();

        /*
         * http://tools.ietf.org/html/rfc3279#section-2.2.3
         * AlgorithmIdentifier ::= SEQUENCE {
         *     algorithm OBJECT IDENTIFIER,
         *     parameters ANY DEFINED BY algorithm OPTIONAL
         * }
         * For ECDSA Signature Algorithm:
         * algorithm: ansi-X9-62 => 1.2.840.10045.2.1
         * parameters: id-ecSigType => 1.2.840.10045.x.y.z
         *
         */
        $asnAlgorithmIdentifier = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'ansi-X9-62' => array(
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ),
                'id-ecSigType' => array(
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ),
            ),
        );

        /*
         * http://tools.ietf.org/html/rfc5280#section-4.1
         * SubjectPublicKeyInfo ::= SEQUENCE {
         *     algorithm AlgorithmIdentifier,
         *     subjectPublicKey BIT STRING
         * }
         */
        $asnSubjectPublicKeyInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'algorithm' => $asnAlgorithmIdentifier,
                'subjectPublicKey' => array(
                    'type' => ASN1::TYPE_BIT_STRING,
                ),
            ),
        );

        $decoded = $asn1->decodeBER(base64_decode($publicKey));
        $mappedDetails = $asn1->asn1map($decoded[0], $asnSubjectPublicKeyInfo);

        return isset($mappedDetails['algorithm']['id-ecSigType']) ? $this->getSupportedECDSACurve() === $mappedDetails['algorithm']['id-ecSigType'] : false;
    }

    /**
     * {@inheritdoc}
     */
    protected function getSupportedPrivateKeyType()
    {
        return defined('OPENSSL_KEYTYPE_EC') ? OPENSSL_KEYTYPE_EC : false;
    }

    /**
     * Returns the ECDSA curve supported in this signer.
     *
     * @return string
     */
    abstract protected function getSupportedECDSACurve();
}
