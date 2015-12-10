<?php

namespace Namshi\JOSE\Signer\SecLib;

use InvalidArgumentException;
use Namshi\JOSE\Signer\SignerInterface;

abstract class PublicKey implements SignerInterface
{
    protected $encryptionAlgorithm;

    /**
     * {@inheritdoc}
     */
    public function sign($input, $key, $password = null)
    {
        if ($password) {
            $this->encryptionAlgorithm->setPassword($password);
        }

        if (!$this->encryptionAlgorithm->loadKey($key)) {
            throw new InvalidArgumentException('Invalid key supplied.');
        }

        return $this->encryptionAlgorithm->sign($input);
    }

    /**
     * {@inheritdoc}
     */
    public function verify($key, $signature, $input)
    {
        if (!$this->encryptionAlgorithm->loadKey($key)) {
            throw new InvalidArgumentException('Invalid key supplied.');
        }

        return $this->encryptionAlgorithm->verify($input, $signature);
    }
}
