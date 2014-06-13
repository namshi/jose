<?php

namespace Namshi\JOSE\Test;

use PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\JWT;

class JWTTest extends TestCase
{
    public function testGenerationOfTheSigninInput()
    {
        $payload = array('a' => 'b');
        $header = array('a' => 'b');
        $jwt = new JWT($payload, $header);

        $this->assertEquals(sprintf("%s.%s", base64_encode(json_encode($payload)), base64_encode(json_encode($header))), $jwt->generateSigninInput());
    }
}
