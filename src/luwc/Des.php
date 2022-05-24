<?php

namespace luwc;
/**
 * Class Des
 * @package luwc
 * @author: luwc
 * @Time: 2022/5/24 16:56:14
 */
class Des
{
    public static function encrypt($data, $key)
    {
        return bin2hex(openssl_encrypt($data, 'des-ecb', $key));
    }

    public static function decrypt($data, $key)
    {
        if (!is_numeric($data)) {
            return openssl_decrypt(hex2bin($data), 'des-ecb', $key);
        }
        return false;

    }

    public static function hash($data)
    {
        return hash('ripemd256', $data, false);
    }

    /**
     * 加密数字方法
     *   echo idEncode(222);
     * @param int $int 要加密的数字
     * @return string 加密后的字符串
     */
    static function idEncode($int)
    {
        $str  = md5($int);
        $sarr = str_split($str);
        $stai = (ord($str) + 8) % 10;
        if ($stai == 0) $stai = 8;

        $idstr = base_convert($int * $stai, 10, 32);

        $str1 = substr($str, 10, 2);
        $str2 = substr($str, 14, 2);
        $str3 = substr($str, 18, 2);
        return strtoupper($str1 . $idstr . $str2 . $str3 . $stai);
    }

    /**
     * 解密数字方法
     *   echo idDncode("");
     * @param string $str 要解密的数字
     * @return int 解密后的数字
     */
    static function idDecode($str)
    {
        $str   = strtolower($str);
        $idstr = substr(substr($str, 2), 0, -5);
        $ji    = base_convert($idstr, 32, 10);
        $si    = (int)substr($str, -1);
        return floor($ji / $si);
    }

    /**
     * @param $string
     * @param string $key
     * @param int $expiry
     * @return string
     * @author: luwc
     * @Time: 2022/2/16 16:43
     */
    static function dzencrypt($string, $key = '', $expiry = 0)
    {
        $ckey_length = 0;
        $key         = md5($key ? $key : "mycodedesc");
        echo "key=".$key.PHP_EOL;
        $keya        = md5(substr($key, 0, 16));
        $keyb        = md5(substr($key, 16, 16));

        $keyc        = $ckey_length ? substr(md5(microtime()), -$ckey_length) : '';

        $cryptkey    = $keya . md5($keya . $keyc);
        echo "cryptkey=".$cryptkey.PHP_EOL;
        $key_length  = strlen($cryptkey);
        $string      = sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        echo "string=".$string.PHP_EOL;
        $string_length = strlen($string);
        $result        = '';
        $box           = range(0, 255);
        $rndkey        = array();
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        for ($j = $i = 0; $i < 256; $i++) {
            $j       = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp     = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a       = ($a + 1) % 256;
            $j       = ($j + $box[$a]) % 256;
            $tmp     = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result  .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        return $keyc . str_replace('=', '', base64_encode($result));

    }

    /**
     * @param $string
     * @param string $key
     * @param int $expiry
     * @return false|string
     * @author: luwc
     * @Time: 2022/2/16 16:43
     */
    static function dzdecrypt($string, $key = '', $expiry = 0)
    {
        $ckey_length = 4;
        $key         = md5($key ? $key : "mycodedesc");
        echo "key:".$key . PHP_EOL;
        $keya        = md5(substr($key, 0, 16));
        $keyb        = md5(substr($key, 16, 16));
        echo "keyb:".$keyb.PHP_EOL;
        $keyc        = $ckey_length ? substr($string, 0, $ckey_length) : '';
        $cryptkey = $keya . md5($keya . $keyc);

        $key_length = strlen($cryptkey);
        $string     = base64_decode(substr($string, $ckey_length));
        $string_length = strlen($string);
        $result        = '';
        $box           = range(0, 255);
        $rndkey        = array();
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        for ($j = $i = 0; $i < 256; $i++) {
            $j       = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp     = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a       = ($a + 1) % 256;
            $j       = ($j + $box[$a]) % 256;
            $tmp     = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result  .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        echo "res:".$result.PHP_EOL;
        echo "sign:".substr($result, 10, 16).PHP_EOL;
        echo "str:".(substr($result, 26) . $keyb ).PHP_EOL;
        if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
            return substr($result, 26);
        } else {
            return '';
        }
    }

    /**
     *
     * @param string $string 原文或者密文
     * @param string $operation 操作(ENCODE | DECODE), 默认为 DECODE
     * @param string $key 密钥
     * @param int $expiry 密文有效期, 加密时候有效， 单位 秒，0 为永久有效
     * @return string 处理后的 原文或者 经过 base64_encode 处理后的密文
     * @example
     *  $a = authcode('abc', 'ENCODE', 'key');
     *  $b = authcode($a, 'DECODE', 'key'); // $b(abc)
     *
     *  $a = authcode('abc', 'ENCODE', 'key', 3600);
     *  $b = authcode('abc', 'DECODE', 'key'); // 在一个小时内，$b(abc)，否则 $b 为空
     */

    static function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0)
    {
        $ckey_length = 4;
        $key         = md5($key ? $key : "kalvin.cn");
        $keya        = md5(substr($key, 0, 16));
        $keyb        = md5(substr($key, 16, 16));

        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()), -$ckey_length)) : '';
        //echo $keyc . PHP_EOL;
        $cryptkey = $keya . md5($keya . $keyc);


        $key_length = strlen($cryptkey);
        $string     = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        //echo "string:" . $string . PHP_EOL;
        $string_length = strlen($string);
        $result        = '';
        $box           = range(0, 255);
        $rndkey        = array();
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }
        for ($j = $i = 0; $i < 256; $i++) {
            $j       = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp     = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a       = ($a + 1) % 256;
            $j       = ($j + $box[$a]) % 256;
            $tmp     = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result  .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }
        if ($operation == 'DECODE') {
            //echo $result . "\n";
            if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
                return substr($result, 26);
            } else {
                return '';
            }
        } else {
            return $keyc . str_replace('=', '', base64_encode($result));
        }
    }

}
