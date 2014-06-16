<?php

namespace Namshi\JOSE\Signer;

interface SignerInterface
{
    /**
     * Signs the $input with the $key, after hashing it.
     *
     * @param  type        $input
     * @param  type        $key
     * @return string|null
     */
    public function sign($input, $key);

    /**
     * Verifies that the input correspond to the $signature decrypted with the
     * given public $key.
     *
     * @param  type    $key
     * @param  type    $signature
     * @param  type    $input
     * @return boolean
     */
    public function verify($key, $signature, $input);
}
