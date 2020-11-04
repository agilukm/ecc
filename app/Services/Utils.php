<?php
namespace App\Services;

class Utils {
    
    public static function hex2bin($str) {
        return hex2bin(strlen($str) % 2 == 1 ? "0" . $str : $str);
    }
    
    public static function substring($str, $start, $end) {
        return substr($str, $start, $end - $start);
    }
    
    public static function arrayValue($array, $key, $default = false) {
        return array_key_exists($key, $array) ? $array[$key] : $default;
    }
}
