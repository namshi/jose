<?php

namespace Namshi\JOSE\Signer\OpenSSL;

use Namshi\JOSE\Signer\SignerInterface;

/**
 * This class is the base of all HMAC Signers.
 */
abstract class HMAC implements SignerInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign($input, $key)
    {
        return hash_hmac($this->getHashingAlgorithm(), $input, (string) $key, true);
    }

    /**
     * To prevent timing attacks we are using PHP 5.6 native function hash_equals,
     * in case of PHP < 5.6 a timing safe equals comparison function.
     *
     * more info here:
     *  http://blog.ircmaxell.com/2014/11/its-all-about-time.html
     *
     *
     * {@inheritdoc}
     */
    public function verify($key, $signature, $input)
    {
        $signedInput = $this->sign($input, $key);

        if (version_compare(PHP_VERSION, '5.6.0', '>=')) {
            return hash_equals($signedInput, $signature);
        }

        return $this->timingSafeEquals($signedInput, $signature);
    }

    /**
     * A timing safe equals comparison.
     *
     * @param string $signature   the internal signature to be checked
     * @param string $signedInput The signed input submitted value
     *
     * @return bool true if the two strings are identical.
     */
    public function timingSafeEquals($known, $input)
    {
        $knownLength = strlen($known);
        $inputLength = strlen($input);

        if (\function_exists('mb_strlen')) {
            $knownLength = \mb_strlen($known, '8bit');
            $inputLength = \mb_strlen($input);
        }

        $result = 0;

        if ($knownLength !== $inputLength) {
            return false;
        }

        for ($i = 0; $i < $inputLength; ++$i) {
            $result |= (ord($known[$i]) ^ ord($input[$i]));
        }

        return $result === 0;
    }

    /**
     * Returns the hashing algorithm used in this signer.
     *
     * @return string
     */
    abstract public function getHashingAlgorithm();
}
