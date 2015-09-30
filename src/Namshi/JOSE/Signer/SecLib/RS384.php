<?php

namespace Namshi\JOSE\Signer\SecLib;

class RS384 extends RSA
{
    /**
     * {@inheritdoc}
     */
    protected function configureEncryptionAlgorithm(\Crypt_RSA $encryptionAlgorithm)
    {
        $encryptionAlgorithm->setHash('sha384');
        $encryptionAlgorithm->setMGFHash('sha384');
    }
}
