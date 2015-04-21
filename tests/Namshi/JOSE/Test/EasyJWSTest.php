<?php

namespace Namshi\JOSE\Test;

use PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\EasyJWS;
use DateTime;

class EasyJWSTest extends TestCase
{
    const SSL_KEY_PASSPHRASE = 'tests';

    public function setup()
    {
        $date       = new DateTime('tomorrow');
        $data       = array(
            'a'     => 'b',
            'exp'   => $date->format('U')
        );
        $this->jws  = new EasyJWS(array('alg' => 'RS256'));
        $this->jws->setPayload($data);
    }

    public function testConstruction()
    {
        $this->assertSame($this->jws->getHeader(), array('alg' => 'RS256', 'typ' => 'JWS'));
        $this->assertRegExp('/^\d+$/', $this->jws->getPayload()['iat'], 'iat property has integer value (from construction)');
    }

    public function testValidationOfAValidEasyJWS()
    {
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws        = EasyJWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH . "public.key");
        $this->assertTrue($jws->isValid($public_key, 'RS256'));
    }

    public function testValidationOfInvalidEasyJWS()
    {
        $date       = new DateTime('yesterday');
        $this->jws->setPayload(array(
            'exp' => $date->format('U')
        ));
        $privateKey = openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", self::SSL_KEY_PASSPHRASE);
        $this->jws->sign($privateKey);

        $jws        = EasyJWS::load($this->jws->getTokenString());
        $public_key = openssl_pkey_get_public(SSL_KEYS_PATH . "public.key");
        $this->assertFalse($jws->isValid($public_key, 'RS256'));
    }
}
