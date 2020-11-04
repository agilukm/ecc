<?php

use Illuminate\Http\Request;
/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/
    Route::get('/', function () {
        return view('welcome');
    });

    Route::get('/ecdsa', "ECCController@ecdsa");
    Route::get('/eddsa', "ECCController@eddsa");
    Route::get('/ecdh', "ECCController@ecdh");
    Route::get('/ecDirect', "ECCController@ecDirect");
    Route::get('/encrypt', "ECCController@encrypt");

    Route::get("/rsa", function () {
        $data = "String to encrypt";
    
        $privKey = openssl_pkey_get_public('file:///C:/Users/Agi/Desktop/Tugas/enkripsi/ecc/routes/id_rsa');
        $encryptedData = "";
        openssl_private_encrypt($data, $encryptedData, $privKey);
        echo 'Encrypted: ' . $encryptedData;

        $pubKey = openssl_pkey_get_public('file:///C:/Users/Agi/.ssh/id_rsa');
        $decryptedData = "";
        openssl_public_decrypt($encryptedData, $decryptedData, $pubKey);
        echo "\n---\nDecrypted: " . $decryptedData;

        echo "\n[OK]\n";
    });

    Route::get("/rsa/2", function (Request $request) {
        $public_key = file_get_contents('C:\Users\Agi\Desktop\Tugas\enkripsi\ecc\routes\public_rsa.pem');
        $private_key = file_get_contents('C:\Users\Agi\Desktop\Tugas\enkripsi\ecc\routes\private_rsa.pem');
        $json_data = $request->get('message');

        $encTime = microtime(true);
        $encrypted = '';
        print openssl_public_encrypt($json_data, $encrypted, $public_key)."\n";
        $encTimeEnd = microtime(true);
        $data['text'] = $json_data;
        $data['encrypt time'] = $encTimeEnd - $encTime;
        $data['Chiper Text'] = $encrypted;
        $data['Base 64 Encoded Chiper'] = base64_encode($encrypted);
        $encTime = microtime(true);
        $decTime = microtime(true);
        $decrypted = '';
        print openssl_private_decrypt(base64_decode($data['Base 64 Encoded Chiper']), $decrypted, $private_key)."\n";
        $decTimeEnd = microtime(true);
        $data['decode_time'] = $decTimeEnd - $decTime;
        $data['Decrypted text'] = $decrypted;

        dd($data);
    });

    Route::get("/ec", "ECCController@ec");
    Route::post("/sign/rsa", "RSAController@sign");
    Route::post("/verify/rsa", "RSAController@verify");
    Route::post("/sign/ecc", "ECCController@sign");
    Route::post("/verify/ecc", "ECCController@verify");
    Route::get("/both/rsa", "RSAController@both");

    Route::get('signed_certificate', function(Request $request) {
    // set certificate file
    $certificate = file_get_contents('file:///C:/xampp/htdocs/ecc/routes/tcpdf.crt');
        // set additional information in the signature
        $info = array(
            'Name' => 'TCPDF',
            'Location' => 'Office',
            'Reason' => 'Testing TCPDF',
            'ContactInfo' => 'http://www.tcpdf.org',
        );
        // set document signature
        PDF::setSignature($certificate, $certificate, 'tcpdfdemo', '', 2, $info);

        PDF::SetFont('helvetica', '', 12);
        PDF::AddPage();

        // print a line of text
        $text = view('tcpdf');

        // add view content
        PDF::writeHTML($text, true, 0, true, 0);

        // add image for signature
        PDF::Image(file_get_contents('file:///C:/xampp/htdocs/ecc/public/tcpdf.png'), 180, 60, 15, 15, 'PNG');

        // define active area for signature appearance
        PDF::setSignatureAppearance(180, 60, 15, 15);

        // save pdf file
        PDF::Output(public_path('hello_world.pdf'), 'F');

        PDF::reset();
        
        return response()->file(public_path('hello_world.pdf'));
    });

    