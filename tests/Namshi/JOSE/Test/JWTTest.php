<?php

namespace Namshi\JOSE\Test;

use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use Namshi\JOSE\JWT;
use PHPUnit_Framework_TestCase as TestCase;

class JWTTest extends TestCase
{
    public function testGenerationOfTheSigninInput()
    {
        $payload = ['b' => 'a', 'iat' => 1421161177];
        $header = ['a' => 'b'];
        $jwt = new JWT($payload, $header);
        $encoder = new Base64UrlSafeEncoder();

        $this->assertEquals(sprintf('%s.%s', $encoder->encode(json_encode($header)), $encoder->encode(json_encode($payload))), $jwt->generateSigninInput());
    }

    public function testGenerationOfTheSigninInputCanHandleSlashes()
    {
        $encoder = new Base64UrlSafeEncoder();
        $json_string = '{"a":"/b/"}';
        $encoded_json_string = $encoder->encode($json_string);
        $jwt = new JWT(json_decode($json_string, true), json_decode($json_string, true));

        $this->assertEquals(sprintf('%s.%s', $encoded_json_string, $encoded_json_string), $jwt->generateSigninInput());
    }

    public function testPayload()
    {
        $jwt = new JWT(['a' => 'b'], []);
        $payload = $jwt->getPayload();

        $this->assertSame(['a' => 'b'], $payload);

        $jwt = new JWT(['a' => 'b'], []);
        $jwt->setPayload(['b' => 'a']);
        $payload = $jwt->getPayload();

        $this->assertSame($payload['b'], 'a');
        $this->assertSame(['b' => 'a'], $payload);
    }
}
