<?php

namespace Namshi\JOSE\Signer\OpenSSL;

/**
 * Class responsible to sign inputs with the ECDSA algorithm, after hashing it.
 */
class ES256 extends ECDSA
{

    public function getHashingAlgorithm()
    {
        return version_compare(phpversion(), '5.4.8', '<') ? 'SHA256' : OPENSSL_ALGO_SHA256;
    }

    protected function getSupportedECDSACurve()
    {
        return '1.2.840.10045.3.1.7';
    }

}
