<?php

namespace Namshi\JOSE\Test;

use Namshi\JOSE\Base64\Base64Encoder;
use Namshi\JOSE\JWS;
use PHPUnit_Framework_TestCase as TestCase;

/**
 * BC test for base64 url-safe fix
 * Test that tokens generated the old way (non url-safe) will work with url-safe base64 decoding.
 */
class BCJWSTest extends TestCase
{
    const SSL_KEY_PASSPHRASE = 'tests';

    public function testTestBC()
    {
        $data = array(
            array('order_nr' => 'ae123123'),
            array('username' => 'asdasdasd'),
            array('anything' => '!@#$%^&*()_+'),
        );

        foreach ($data as $payload) {
            $jwsOld = new JWS(array('alg' => 'RS256'));
            $jwsOld->setEncoder(new Base64Encoder());
            $jwsOld->setPayload($payload);
            $jwsOld->sign(openssl_pkey_get_private(SSL_KEYS_PATH.'private.key', self::SSL_KEY_PASSPHRASE));

            $t = $jwsOld->getTokenString();

            $jwsNew = JWS::load($t);
            $this->assertTrue($jwsNew->verify(openssl_pkey_get_public(SSL_KEYS_PATH.'public.key')));
        }
    }
}
