<?php

namespace Namshi\JOSE\Base64;

class Base64Encoder implements Encoder
{
    /**
     * {@inheritdoc}
     */
    public function encode($data)
    {
        return base64_encode($data);
    }

    /**
     * {@inheritdoc}
     */
    public function decode($data)
    {
        return base64_decode($data);
    }
}
