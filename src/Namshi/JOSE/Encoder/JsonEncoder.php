<?php

namespace Namshi\JOSE\Encoder;

class JsonEncoder implements Encoder
{
    /**
     * @param string $data
     *
     * @return string
     */
    public function encode($data)
    {
        return json_encode($data, JSON_UNESCAPED_SLASHES);
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public function decode($data)
    {
        return json_decode($data, true);
    }
}
