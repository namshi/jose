<?php

namespace Namshi\JOSE\Signer\SecLib;

class RS512 extends RSA
{
    /**
     * {@inheritdoc}
     */
    protected function configureEncryptionAlgorithm(\Crypt_RSA $encryptionAlgorithm)
    {
        $encryptionAlgorithm->setHash('sha512');
        $encryptionAlgorithm->setMGFHash('sha512');
    }
}
