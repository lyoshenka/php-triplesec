<?php

foreach (array_merge(glob(__DIR__.'/../ext/req_check.php'), [__DIR__.'/../src/RngInterface.class.php'], glob(__DIR__.'/../src/*.php')) as $file)
{
  require_once $file;
}

use lyoshenka\TripleSec;
use lyoshenka\TripleSecInvalidKeyException;
use lyoshenka\ReplayRng;

function testCycle()
{
  $plainText = '1234567890-';
  $password  = '42';

  $cipherText   = TripleSec::encrypt($plainText, $password);
  $newPlaintext = TripleSec::decrypt($cipherText, $password);

  return $newPlaintext === $plainText;
}

function testVector()
{
  $cipherText =
    '1c94d7de0000000359a5e5d60f09ebb6bc3fdab6642725e03bc3d51e167fa60327df567476d467f8b6ce65a909b4f582443f230ff10a36f60315ebce1cf1395d7b763c768764207f4f4cc5207a21272f3a5542f35db73c94fbc7bd551d4d6b0733e0b27fdf9606b8a26d45c4b79818791b6ae1ad34c23e58de482d454895618a1528ec722c5218650f8a2f55f63a6066ccf875f46c9b68ed31bc1ddce8881d704be597e1b5006d16ebe091a02e24d569f3d09b0578d12f955543e1a1f1dd75784b8b4cba7ca0bb7044389eb6354cea628a21538d';
  $password   = '42';

  try
  {
    return TripleSec::decrypt($cipherText, $password) === 'ciao';
  }
  catch (TripleSecInvalidKeyException $e)
  {
    return false;
  }
}

function testBadPw()
{
  $cipherText =
    '1c94d7de0000000359a5e5d60f09ebb6bc3fdab6642725e03bc3d51e167fa60327df567476d467f8b6ce65a909b4f582443f230ff10a36f60315ebce1cf1395d7b763c768764207f4f4cc5207a21272f3a5542f35db73c94fbc7bd551d4d6b0733e0b27fdf9606b8a26d45c4b79818791b6ae1ad34c23e58de482d454895618a1528ec722c5218650f8a2f55f63a6066ccf875f46c9b68ed31bc1ddce8881d704be597e1b5006d16ebe091a02e24d569f3d09b0578d12f955543e1a1f1dd75784b8b4cba7ca0bb7044389eb6354cea628a21538d';
  $password   = '423';

  try
  {
    TripleSec::decrypt($cipherText, $password);
    return false;
  }
  catch (TripleSecInvalidKeyException $e)
  {
    return true;
  }
}

function testSpec()
{
  $spec = json_decode(file_get_contents(__DIR__ . '/triplesec_spec_v3.js'), true);

  $count = 1;

  foreach ($spec['vectors'] as $vector)
  {
    echo "  Vector $count\n";

    $rng = new ReplayRng(hex2bin($vector['r']));
    $pt = hex2bin($vector['pt']);
    $ct = hex2bin($vector['ct']);
    $key = hex2bin($vector['key']);

    $cipherText = TripleSec::encrypt($pt, $key, $rng);
    echo "    Ciphertext match ... " . (hex2bin($cipherText) === $ct ? 'pass' : 'fail') . "\n";

    $plainText = TripleSec::decrypt($cipherText, $key);
    echo "    Plaintext match ... " . ($plainText === $pt ? 'pass' : 'fail') . "\n";

    $count++;
  }
}

echo "cycle test ... ";
$result1 = testCycle();
echo $result1 === true ? "pass" : "fail";
echo "\n";

echo "vector test ... ";
$result2 = testVector();
echo $result2 === true ? "pass" : "fail";
echo "\n";

echo "bad pw test ... ";
$result3 = testBadPw();
echo $result3 === true ? "pass" : "fail";
echo "\n";

echo "spec tests:\n";
testSpec();
echo "done\n";
