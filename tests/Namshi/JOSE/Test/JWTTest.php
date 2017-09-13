<?php

namespace Namshi\JOSE\Test;

use Namshi\JOSE\Encoder\Base64UrlSafeEncoder;
use Namshi\JOSE\Encoder\JsonEncoder;
use Namshi\JOSE\JWT;
use PHPUnit_Framework_TestCase as TestCase;

class JWTTest extends TestCase
{
    public function testGenerationOfTheSigninInput()
    {
        $payload = array('b' => 'a', 'iat' => 1421161177);
        $header = array('a' => 'b');
        $jwt = new JWT($payload, $header);
        $base64Encoder = new Base64UrlSafeEncoder();
        $jsonEncoder = new JsonEncoder();

        $this->assertEquals(sprintf('%s.%s', $base64Encoder->encode($jsonEncoder->encode($header)), $base64Encoder->encode($jsonEncoder->encode($payload))), $jwt->generateSigninInput());
    }

    public function testGenerationOfTheSigninInputCanHandleSlashes()
    {
        $base64Encoder= new Base64UrlSafeEncoder();
        $jsonEncoder = new JsonEncoder();
        $json_string = '{"a":"/b/"}';
        $encoded_json_string = $base64Encoder->encode($json_string);
        $jwt = new JWT($jsonEncoder->decode($json_string), $jsonEncoder->decode($json_string));

        $this->assertEquals(sprintf('%s.%s', $encoded_json_string, $encoded_json_string), $jwt->generateSigninInput());
    }

    public function testPayload()
    {
        $jwt = new JWT(array('a' => 'b'), array());
        $payload = $jwt->getPayload();

        $this->assertSame(array('a' => 'b'), $payload);

        $jwt = new JWT(array('a' => 'b'), array());
        $jwt->setPayload(array('b' => 'a'));
        $payload = $jwt->getPayload();

        $this->assertSame($payload['b'], 'a');
        $this->assertSame(array('b' => 'a'), $payload);
    }
}
