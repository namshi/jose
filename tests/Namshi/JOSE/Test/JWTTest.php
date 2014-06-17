<?php

namespace Namshi\JOSE\Test;

use PHPUnit_Framework_TestCase as TestCase;
use Namshi\JOSE\JWT;
use Namshi\JOSE\Base64;

class JWTTest extends TestCase
{
    public function testGenerationOfTheSigninInput()
    {
        $payload = array('a' => 'b', 'iat'=>1403033066);
        $header = array('a' => 'b');
        $jwt = new JWT($payload, $header);

        $this->assertEquals(sprintf("%s.%s", Base64::encode(json_encode($header)), Base64::encode(json_encode($payload))), $jwt->generateSigninInput());
    }

    public function testTokenIsNotExpired()
    {
        $tomorrow = new \DateTime('tomorrow');
        $token = new JWT(array('exp'=> $tomorrow->format('U') ), array());
        $method = self::getMethod('isExpired');

        $this->assertFalse($method->invokeArgs($token,array()));
    }

    public function testTokenIsExpired()
    {
        $yesterday = new \DateTime('yesterday');
        $token = new JWT(array('exp'=> $yesterday->format('U') ), array());
        $method = self::getMethod('isExpired');

        $this->assertTrue($method->invokeArgs($token,array()));
    }

    public function testTokenExpirationDateIsNotDefined()
    {
        $token = new JWT(array(), array());
        $method = self::getMethod('isExpired');

        $this->assertFalse($method->invokeArgs($token,array()));
    }

    /**
     * @param string $name
     */
    protected static function getMethod($name)
    {
        $class = new \ReflectionClass('Namshi\JOSE\JWT');
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }
}
