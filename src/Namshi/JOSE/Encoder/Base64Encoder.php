<?php

namespace Namshi\JOSE\Encoder;

class Base64Encoder implements Encoder
{
    /**
     * @param string $data
     *
     * @return string
     */
    public function encode($data)
    {
        return base64_encode($data);
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public function decode($data)
    {
        return base64_decode($data);
    }
}
