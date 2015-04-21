<?php

namespace Namshi\JOSE\Test\OpenSSL\Signer;

use \PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\Signer\OpenSSL\RS256;

class PublicKeyTest extends TestCase
{
    public function setup()
    {
        $this->privateKeyResource = openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", 'tests');
        $this->privateKeyString   = "-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAN91kQxBuaze3WjI\nCNjeR/HD8E3kDzp89+Lhtn3tMish4yQxhNl6BEkabuS3pUj3WDP6+AFjBVqA1j3f\nu8Wqu7hRJDPHOs2kCII+LhIqvqQTLx/nvNOUhW2DimKn0HuHnlwJODq0MHFJEq5R\nrJH+mFGsP9yMGz4MxA04E2RVbUJRAgMBAAECgYEAjrDrO3Fo2GvD5Jn/lER0mnxt\nIb/kvYt5WyaYutbRN1u/SKhaVeklfWzkrSZb5DkV2LOE1JXfoEgvBnms1O9OSJXw\nqDrFF7NDebw95g6JzI+SbkIHw0Cb+/E9K92FjvW3Bi8j9PKIa8c/dpwIAIirc/q8\nuhSTf4WoIOHSFbSaQPECQQD1Wi9vynJLI5lShOs0wPomZOwNrXa73Lj8ciZC4oPS\nt6tWjbLnLsP+vTSLUyEYeQGsjdbY+y5siJmAqnV/ShB9AkEA6Sgna9gQw4dXN0jB\nSjOZSjl4S2/H3wHatclrvlYfbJVU6GlIlqWGaUkdFvCuEr9iXJAY4zpEQ4P370EZ\ntsyVZQJBAOZu/X6RNSc9GBNYo0+4rzjAMLPn50wp0dPHogfPlt+hgVqZWx2l3o6y\nRVdVjA/gFqJp1Q+VWdS1tvYRIqmadkECQCVdqQuwgedEHmcewtNod42crjmwvWBx\nBKMTl6/WT4zwVb41eUujVWo0LHRLuCoK//GDqmloIh6L3MU8MqnIGb0CQFWcpD4/\nroCkMblk0hPoQPpyapJexc438x7XuEGFEhyxxauqC5R4YFKCf+KBS2gZgr4GSwBU\nQww+qZ3eRYM7faM=\n-----END PRIVATE KEY-----";
        $this->privateKeyFilePath = SSL_KEYS_PATH . 'private-ne.key';
        $this->publicKeyResource  = openssl_pkey_get_public(SSL_KEYS_PATH . "public.key");
        $this->publicKeyString   = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDfdZEMQbms3t1oyAjY3kfxw/BN\n5A86fPfi4bZ97TIrIeMkMYTZegRJGm7kt6VI91gz+vgBYwVagNY937vFqru4USQz\nxzrNpAiCPi4SKr6kEy8f57zTlIVtg4pip9B7h55cCTg6tDBxSRKuUayR/phRrD/c\njBs+DMQNOBNkVW1CUQIDAQAB\n-----END PUBLIC KEY-----";
        $this->publicKeyFilePath = SSL_KEYS_PATH . 'public-ne.key';
        $this->signer       = new RS256;
    }

    public function testStringKeyWorksProperly()
    {
        $encrypted = $this->signer->sign('aaa', $this->privateKeyString);
        $this->assertInternalType('bool', $this->signer->verify($this->publicKeyString, $encrypted, 'aaa'));
        $this->assertTrue($this->signer->verify($this->publicKeyString, $encrypted, 'aaa'));
    }

    public function testFilePathKeyWorksProperly()
    {
        $encrypted = $this->signer->sign('aaa', $this->privateKeyFilePath);
        $this->assertInternalType('bool', $this->signer->verify($this->publicKeyFilePath, $encrypted, 'aaa'));
        $this->assertTrue($this->signer->verify($this->publicKeyFilePath, $encrypted, 'aaa'));
    }

    public function testResourceKeyWorksProperly()
    {
        $encrypted = $this->signer->sign('aaa', $this->privateKeyResource);
        $this->assertInternalType('bool', $this->signer->verify($this->publicKeyResource, $encrypted, 'aaa'));
        $this->assertTrue($this->signer->verify($this->publicKeyResource, $encrypted, 'aaa'));
    }
}
