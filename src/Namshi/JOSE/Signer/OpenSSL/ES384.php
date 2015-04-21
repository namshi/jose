<?php

namespace Namshi\JOSE\Signer\OpenSSL;

/**
 * Class responsible to sign inputs with the ECDSA algorithm, after hashing it.
 */
class ES384 extends ECDSA
{

    public function getHashingAlgorithm()
    {
        return version_compare(phpversion(), '5.4.8', '<') ? 'SHA384' : OPENSSL_ALGO_SHA384;
    }

    protected function getSupportedECDSACurve()
    {
        return '1.3.132.0.34';
    }

}
