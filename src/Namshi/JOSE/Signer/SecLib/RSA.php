<?php

namespace Namshi\JOSE\Signer\SecLib;

use Namshi\JOSE\Signer\SignerInterface;

abstract class RSA implements SignerInterface
{
    private $encryptionAlgorithm;

    public function __construct()
    {
        $encryptionAlgorithm = new \Crypt_RSA();

        $this->configureEncryptionAlgorithm($encryptionAlgorithm);

        $this->encryptionAlgorithm = $encryptionAlgorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function sign($input, $key, $password = null)
    {
        if ($password) {
            $this->encryptionAlgorithm->setPassword($password);
        }

        if (!$this->encryptionAlgorithm->loadKey($key)) {
            throw new \InvalidArgumentException('Invalid key supplied.');
        }

        return $this->encryptionAlgorithm->sign($input);
    }

    /**
     * {@inheritdoc}
     */
    public function verify($key, $signature, $input)
    {
        if (!$this->encryptionAlgorithm->loadKey($key)) {
            throw new \InvalidArgumentException('Invalid key supplied.');
        }

        return $this->encryptionAlgorithm->verify($input, $signature);
    }

    /**
     * @param \Crypt_RSA $encryptionAlgorithm
     */
    abstract protected function configureEncryptionAlgorithm(\Crypt_RSA $encryptionAlgorithm);
}
