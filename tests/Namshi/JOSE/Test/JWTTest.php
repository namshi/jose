<?php

namespace Namshi\JOSE\Test;

use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\JWT;

class JWTTest extends TestCase
{
    public function testGenerationOfTheSigninInput()
    {
        $payload = array('b' => 'a', 'iat' => 1421161177);
        $header = array('a' => 'b');
        $jwt = new JWT($payload, $header);
        $encoder = new Base64UrlSafeEncoder();

        $this->assertEquals(sprintf("%s.%s", $encoder->encode(json_encode($header)), $encoder->encode(json_encode($payload))), $jwt->generateSigninInput());
    }

    public function testPayload()
    {
        $jwt = new JWT(array('a' => 'b'), array());
        $payload = $jwt->getPayload();

        $this->assertSame($payload['a'], 'b');
        $this->assertRegExp('/^\d+$/', $payload['iat'], 'iat property has integer value (from construction)');

        $jwt = new JWT(array('a' => 'b'), array());
        $jwt->setPayload(array('b' => 'a'));
        $payload = $jwt->getPayload();

        $this->assertSame($payload['b'], 'a');
        $this->assertRegExp('/^\d+$/', $payload['iat'], 'iat property has integer value (from set)');

        $jwt = new JWT(array('a' => 'b'), array());
        $jwt->setPayload(array('b' => 'a'), false);
        $payload = $jwt->getPayload();

        $this->assertSame($payload['b'], 'a');
        $this->assertFalse(isset($payload['iat']), 'no iat property (from set with auto claim off)');
    }
}
