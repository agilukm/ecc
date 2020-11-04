<?php
namespace App\Http\Controllers;

use phpseclib\Crypt\RSA;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

class RSAController extends BaseController
{
    
    public function sign(Request $request)
    {
        $encryptTime = microtime(true);
        $rsa = new RSA();
        $plaintext = $request->get('text');
        $rsa->loadKey(file_get_contents('file:///C:/Users/Agi/Desktop/Tugas/enkripsi/ecc/routes/private_rsa.pem')); // private key
        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $signature = $rsa->sign($plaintext);
        $encryptTimeEnd = microtime(true);
        $data['time'] = $encryptTimeEnd - $encryptTime; 
        $data['signature'] = base64_encode($signature);
        return $data;
    }
    
    public function verify(Request $request)
    {
        $verifyTime = microtime(true);
        $rsa = new RSA();
        $plaintext = $request->get('text');
        $rsa->loadKey(file_get_contents('file:///C:/Users/Agi/Desktop/Tugas/enkripsi/ecc/routes/public_rsa.pem')); // public key
        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $signature = base64_decode($request->get('signature'));

        $status = $rsa->verify($plaintext, $signature) ? true : false;
        $verifyTimeEnd = microtime(true);
        $data['time'] = $verifyTimeEnd - $verifyTime;
        $data['verify'] = $status;
        return $data;
    }

    public function both()
    {
        $rsa = new RSA();
        $encryptTime = microtime(true);
        $plaintext = 'aku adalah anak gembala selalu riang serta gembira na nana na na na na na nana nana nanana';
        $rsa->loadKey(file_get_contents('file:///C:/Users/Agi/Desktop/Tugas/enkripsi/ecc/routes/private_rsa.pem')); // private key
        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
        $signature = $rsa->sign($plaintext);
        $encryptTimeEnd = microtime(true);
        $data['sign time'] = $encryptTimeEnd - $encryptTime; 
        $verifyTime = microtime(true);
        $rsa->loadKey(file_get_contents('file:///C:/Users/Agi/Desktop/Tugas/enkripsi/ecc/routes/public_rsa.pem')); // public key
        $status = $rsa->verify($plaintext, $signature) ? true : false;
        $verifyTimeEnd = microtime(true);
        $data['verify time'] = $verifyTimeEnd - $verifyTime;
        $data['verify'] = $status;
        return $data;
    }
}
