<?php

require_once __DIR__.'/Triplesec.class.php';


$key = 'wizardofoz';
$plaintext = "There's no place like home!";

echo "Key: '$key'\n";
echo "Plaintext: '$plaintext'\n";

$ciphertext = TripleSec::encrypt($plaintext, $key);

echo "Ciphertext: '$ciphertext'\n";

$backToPlaintext = TripleSec::decrypt($ciphertext, $key);

echo "Back to plaintext: '$backToPlaintext'\n";

