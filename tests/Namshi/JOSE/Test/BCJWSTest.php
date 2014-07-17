<?php

namespace Namshi\JOSE\Test;

use Namshi\JOSE\JWS;
use PHPUnit_Framework_TestCase as TestCase;

/**
 * BC test for base64 url-safe fix
 * Test that tokens generated the old way (non url-safe) will work with url-safe base64 decoding
 */
class BCJWSTest extends TestCase
{
    const SSL_KEY_PASSPHRASE = 'tests';

    public function testTestBC()
    {
        $data = [
            ["order_nr" => "ae123123"],
            ["username" => "asdasdasd"],
            ["anything" => "!@#$%^&*()_+"]
        ];

        foreach ($data as $payload) {
            $jwsOld = new JWSBase64("RS256");
            $jwsOld->setPayload($payload);
            $jwsOld->sign(openssl_pkey_get_private(SSL_KEYS_PATH . "private.key", self::SSL_KEY_PASSPHRASE));

            $t = $jwsOld->getTokenString();

            $jwsNew = JWS::load($t);
            $this->assertTrue($jwsNew->verify(openssl_pkey_get_public(SSL_KEYS_PATH . "public.key")));
        }
    }

}

class JWSBase64 extends JWS
{

    protected static function base64decode($data)
    {
        return base64_decode($data);
    }

    protected static function base64encode($data)
    {
        return base64_encode($data);
    }

}
