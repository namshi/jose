<?php

namespace Namshi\JOSE\Signer;

/**
 * Class responsible to sign inputs with the RSA algorithm, after hashing it.
 */
class RS512 extends RSA
{
    public function getHashingAlgorithm()
    {
        return version_compare(phpversion(), '5.4', '<') ? 'SHA512' : OPENSSL_ALGO_SHA512;
    }
}
