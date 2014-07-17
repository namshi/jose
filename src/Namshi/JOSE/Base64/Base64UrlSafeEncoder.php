<?php

namespace Namshi\JOSE\Base64;

class Base64UrlSafeEncoder extends Base64Encoder
{

    public function encode($data)
    {
        return rtrim(strtr(base64_encode(parent::encode($data)), '+/', '-_'), '=');
    }

    public function decode($data)
    {
        return base64_decode(strtr(parent::decode($data), '-_', '+/'));
    }

}
