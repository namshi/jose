<?php

namespace Namshi\JOSE\Test;

use DateTime;
use Namshi\JOSE\SimpleJWS;
use PHPUnit_Framework_TestCase as TestCase;

class SimpleJWSTest extends TestCase
{
    const SSL_KEY_PASSPHRASE = 'tests';

    public function setup()
    {
        $date = new DateTime('tomorrow');
        $data = array(
            'a' => 'b',
            'exp' => $date->format('U'),
        );
        $this->jws = new SimpleJWS(array('alg' => 'RS256'));
        $this->jws->setPayload($data);
    }

    public function testConstruction()
    {
        $this->assertSame($this->jws->getHeader(), array('alg' => 'RS256', 'typ' => 'JWS'));
        $this->assertTrue(is_int($this->jws->getPayload()['iat']), 'iat property should be integer value (from construction)');
    }

    public function testValidationOfAValidSimpleJWS()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws = SimpleJWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
        $this->assertTrue($jws->isValid($public_key, 'RS256'));
    }

    public function testValidationOfInvalidSimpleJWS()
    {
        $date = new DateTime('yesterday');
        $this->jws->setPayload(array(
            'exp' => $date->format('U'),
        ));
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws = SimpleJWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
        $this->assertFalse($jws->isValid($public_key, 'RS256'));
    }

    public function testValidationOfValidSimpleJWSWithStringIat()
    {
        $date = new DateTime('tomorrow');
        $data = array(
            'a' => 'b',
            'exp' => $date->format('U'),
            'iat' => time()
        );
        $this->jws->setPayload($data);

        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws = SimpleJWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
        $this->assertTrue($jws->isValid($public_key, 'RS256'));
    }

    public function testValidationOfValidSimpleJWSWithExpAsInt()
    {
        $date = new DateTime('tomorrow');
        $data = array(
            'a' => 'b',
            'exp' => $date->getTimestamp(),
            'iat' => time()
        );
        $this->jws->setPayload($data);

        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws = SimpleJWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
        $this->assertTrue($jws->isValid($public_key, 'RS256'));
    }

    public function testValidationOfInvalidSimpleJWSWithExpAsInt()
    {
        $date = new DateTime('yesterday');
        $data = array(
            'a' => 'b',
            'exp' => $date->getTimestamp(),
            'iat' => time()
        );
        $this->jws->setPayload($data);

        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws = SimpleJWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH.'public.key');
        $this->assertFalse($jws->isValid($public_key, 'RS256'));
    }
}
