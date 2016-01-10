<?php

namespace Namshi\JOSE\Signer;

interface SignerInterface
{
    /**
     * Signs the $input with the $key, after hashing it.
     *
     * @param string          $input
     * @param resource|string $key
     *
     * @return string|null
     */
    public function sign($input, $key);

    /**
     * Verifies that the input correspond to the $signature decrypted with the
     * given public $key.
     *
     * @param resource|string $key
     * @param string          $signature
     * @param string          $input
     *
     * @return bool
     */
    public function verify($key, $signature, $input);
}
