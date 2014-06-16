<?php

namespace Namshi\JOSE\Signer;

/**
 * None Signer
 */
class none implements SignerInterface
{
    /**
     * @inheritdoc
     */
    public function sign($input, $key)
    {
        return '';
    }

    /**
     * @inheritdoc
     */
    public function verify($key, $signature, $input)
    {
        return $signature === '';
    }
}
