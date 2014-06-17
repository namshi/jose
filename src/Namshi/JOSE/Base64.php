<?php

namespace Namshi\JOSE;

/**
 * Encode and Decode in Base64 Url Safe.
 */
class Base64
{
    public static function encode($data)
    {
        return strtr(rtrim(base64_encode($data), '='), '+/', '-_');
    }

    public static function decode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
