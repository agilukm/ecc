<?php
namespace App\Http\Controllers;

use Elliptic\EC;
use Elliptic\EdDSA;
use App\Services\ECIES;
use Mdanter\Ecc\EccFactory;
use Illuminate\Http\Request;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Illuminate\Routing\Controller as BaseController;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PrivateKey\PemPrivateKeySerializer;

class ECCController extends BaseController
{
    
    public function ecdsa()
    {
        $ec = new EC('secp256k1');

        // Generate keys
        $key = $ec->genKeyPair();

        // Sign message (can be hex sequence or array)
        $msg = 'ab4c3451';
        $signature = $key->sign($msg);

        // Export DER encoded signature to hex string
        $derSign = $signature->toDER('hex');

        // Verify signature
        echo "Verified: " . (($key->verify($msg, $derSign) == TRUE) ? "true" : "false") . "\n";

        // CHECK WITH NO PRIVATE KEY

        // Public key as '04 + x + y'
        $pub = "049a1eedae838f2f8ad94597dc4368899ecc751342b464862da80c280d841875ab4607fb6ce14100e71dd7648dd6b417c7872a6ff1ff29195dabd99f15eff023e5";

        // Signature MUST be either:
        // 1) hex-string of DER-encoded signature; or
        // 2) DER-encoded signature as byte array; or
        // 3) object with two hex-string properties (r and s)

        // case 1
        $sig = '30450220233f8bab3f5df09e3d02f45914b0b519d2c04d13ac6964495623806a015df1cd022100c0c279c989b79885b3cc0f117643317bc59414bfb581f38e03557b8532f06603';

        // case 2
        $sig = [48,69,2,32,35,63,139,171,63,93,240,158,61,2,244,89,20,176,181,25,210,192,77,19,172,105,100,73,86,35,128,106,1,93,241,205,2,33,0,192,194,121,201,137,183,152,133,179,204,15,17,118,67,49,123,197,148,20,191,181,129,243,142,3,85,123,133,50,240,102,3];

        // case 3
        $sig = ['r' => '233f8bab3f5df09e3d02f45914b0b519d2c04d13ac6964495623806a015df1cd', 's' => 'c0c279c989b79885b3cc0f117643317bc59414bfb581f38e03557b8532f06603'];


        // Import public key
        $key = $ec->keyFromPublic($pub, 'hex');

        // Verify signature
        echo "Verified: " . (($key->verify($msg, $sig) == TRUE) ? "true" : "false") . "\n";
    }

    public function eddsa()
    {
        // Create and initialize EdDSA context
        // (better do it once and reuse it)
        $ec = new EdDSA('ed25519');

        // Create key pair from secret
        $key = $ec->keyFromSecret('61233ca4590acd'); // hex string or array of bytes

        // Sign message (can be hex sequence or array)
        $msg = 'ab4c3451';
        $signature = $key->sign($msg)->toHex();

        // Verify signature
        echo "Verified: " . (($key->verify($msg, $signature) == TRUE) ? "true" : "false") . "\n";

        // CHECK WITH NO PRIVATE KEY

        // Import public key
        $pub = '2763d01c334250d3e2dda459e5e3f949f667c6bbf0a35012c77ad40b00f0374d';
        $key = $ec->keyFromPublic($pub, 'hex');

        // Verify signature
        $signature = '93899915C2919181A3D244AAAC032CE78EF76D2FFC0355D4BE2C70F48202EBC5F2BB0541D236182F55B11AC6346B524150695E5DE1FEA570786E1CC1F7999404';
        echo "Verified: " . (($key->verify($msg, $signature) == TRUE) ? "true" : "false") . "\n";
    }

    public function ecdh()
    {
        $ec = new EC('curve25519');

        // Generate keys
        $key1 = $ec->genKeyPair();
        $key2 = $ec->genKeyPair();

        $shared1 = $key1->derive($key2->getPublic());
        $shared2 = $key2->derive($key1->getPublic());

        echo "Both shared secrets are BN instances\n";
        echo $shared1->toString(16) . "\n";
        echo $shared2->toString(16) . "\n";
    }

    public function ecDirect()
    {
        $ec = new EC('secp256k1');

        $priv_hex = "751ce088f64404e5889bf7e9e5c280b200b2dc158461e96b921df39a1dbc6635";
        $pub_hex  = "03a319a1d10a91ada9a01ab121b81ae5f14580083a976e74945cdb014a4a52bae6";

        $priv = $ec->keyFromPrivate($priv_hex);
        if ($pub_hex == $priv->getPublic(true, "hex")) {
            echo "Success\n";
        } else {
            echo "Fail\n";
        }
    }

    public function encrypt()
    {
        $encryptTime = microtime(true); 

        $ec = new EC('secp256k1');

        // Generate keys
        $key1Priv = $ec->genKeyPair();
        $key2Priv = $ec->genKeyPair();
        $data = [];
        $data['key1'] = $key1Priv;
        $data['key2'] = $key1Priv;
        $data["Private key 1 : "] = $key1Priv->getPrivate("hex");
        $data["Private key 2 : "] =  $key2Priv->getPrivate("hex");
        // Get public parts from generated keys
        $key1Pub = $ec->keyFromPublic($key1Priv->getPublic());
        $key2Pub = $ec->keyFromPublic($key2Priv->getPublic());
        
        $data["Public key 1 : "] = $key1Pub;
        $data["Public key 2 : "] = $key2Pub;

        // Some text to encrypt
        $text = "hello muthafuckar";
        $data['text'] = $text;
        // Encrypt using private from key1 and public from key2
        $ecies1 = new ECIES($key1Priv, $key2Pub);
        $cipher = $ecies1->encrypt($text);
        $encryptTimeEnd = microtime(true); 
        // Decrypt using private from key2 and public from key1
        $decryptTime = microtime(true); 
        $ecies2 = new ECIES($key2Priv, $key1Pub);
        $decryptedText = $ecies2->decrypt($cipher);
        $decryptTimeEnd = microtime(true); 
        $data['cipher'] = $cipher;
        $data['Decrypted'] = $decryptedText;
        echo "ECIES example\n";
        echo "Source text: " . $text . "\n";
        echo "Cipher: " . bin2hex($cipher) . "\n";
        echo "Decrypted: " . $decryptedText . "\n";
        $data['encrypt_time'] = ($encryptTimeEnd - $encryptTime);
        $data['decrypt_time'] = ($decryptTimeEnd - $decryptTime);
        dd($data);
    }

    public function ec()
    {
        $ec = new EC('secp256k1');

        // Generate keys
        $key1Priv = $ec->genKeyPair();
        $data = [];
        $data["Private key 1 : "] = $key1Priv->getPrivate("hex");
        // Get public parts from generated keys
        $key1Pub = $ec->keyFromPublic($key1Priv->getPublic());
        
        // Some text to encrypt
        $text = "hello muthafuckar";
        $data['text'] = $text;
        // Encrypt using private from key1 and public from key2
        $ecies1 = new ECIES($key1Priv, $key1Pub);

        $encryptTime = microtime(true); 
        $cipher = $ecies1->encrypt($text);
        $encryptTimeEnd = microtime(true); 
        // Decrypt using private from key2 and public from key1
        $decryptTime = microtime(true); 
        $decryptedText = $ecies1->decrypt($cipher);
        $decryptTimeEnd = microtime(true); 

        $data['cipher'] = $cipher;
        $data['Decrypted'] = $decryptedText;
        $data['encrypt_time'] = ($encryptTimeEnd - $encryptTime);
        $data['decrypt_time'] = ($decryptTimeEnd - $decryptTime);
        dd($data);
    }

    public function sign(Request $request)
    {
        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator256();
        $useDerandomizedSignatures = true;
        $algorithm = 'sha256';

        ## You'll be restoring from a key, as opposed to generating one.
        $pemSerializer = new PemPrivateKeySerializer(new DerPrivateKeySerializer($adapter));
       
        $keyData = file_get_contents("file:///C:/xampp/htdocs/ecc/routes/private.ec.key");
        $key = $pemSerializer->parse($keyData);

        $document = $request->get('text');

        $hasher = new SignHasher($algorithm, $adapter);
        $hash = $hasher->makeHash($document, $generator);

        # Derandomized signatures are not necessary, but is avoids
        # the risk of a low entropy RNG, causing accidental reuse
        # of a k value for a different message, which leaks the
        # private key.

        if ($useDerandomizedSignatures) {
            $random = \Mdanter\Ecc\Random\RandomGeneratorFactory::getHmacRandomGenerator($key, $hash, $algorithm);
        } else {
            $random = \Mdanter\Ecc\Random\RandomGeneratorFactory::getRandomGenerator();
        }
        $randomK = $random->generate($generator->getOrder());

        $signer = new Signer($adapter);
        $signStart = microtime(true);
        $signature = $signer->sign($key, $hash, $randomK);
        $signEnd = microtime(true);

        $serializer = new DerSignatureSerializer();
        $serializedSig = $serializer->serialize($signature);
        $data['signature'] = base64_encode($serializedSig) . PHP_EOL;
        $data['time'] = $signEnd - $signStart;
        return $data;
    }

    public function verify(Request $request)
    {
        $start = microtime(true);

        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator384();
        $algorithm = 'sha256';
        $sigData = base64_decode($request->get('signature'));
        $document = $request->get('text');
        // Parse signature
        $sigSerializer = new DerSignatureSerializer();
        $sig = $sigSerializer->parse($sigData);

        // Parse public key
        $keyData = file_get_contents("file:///C:/xampp/htdocs/ecc/routes/public.pem");
        $derSerializer = new DerPublicKeySerializer($adapter);
        $pemSerializer = new PemPublicKeySerializer($derSerializer);
        $key = $pemSerializer->parse($keyData);
        $hasher = new SignHasher($algorithm);
        $hash = $hasher->makeHash($document, $generator);
        $signer = new Signer($adapter);
        $check = $signer->verify($key, $sig, $hash);
        $end = microtime(true);

        $data['verify'] = $check;
        $data['time'] = $end - $start;
        return $data;
    }

}
