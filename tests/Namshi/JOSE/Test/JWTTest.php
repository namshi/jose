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
}
