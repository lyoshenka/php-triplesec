<?php

foreach (['libsodium', 'scrypt', 'mcrypt'] as $extension)
{
  if (!extension_loaded($extension))
  {
    throw new RuntimeException($extension . ' extension required');
  }
}

require_once __DIR__ . '/SHA3.class.php';

class TripleSec
{
  const MAGIC_BYTES = [0x1c, 0x94, 0xd7, 0xde];
  const VERSION     = [0x00, 0x00, 0x00, 0x03];

  const SALT_LENGTH = 16;

  const SCRYPT_N = 2 ** 15;
  const SCRYPT_R = 8;
  const SCRYPT_P = 1;

  const SHA512_KEY_SIZE    = 48;
  const SHA512_OUTPUT_SIZE = 64;
  const SHA512_BLOCK_SIZE  = 128;
  const SHA3_KEY_SIZE      = 48;
  const SHA3_OUTPUT_SIZE   = 64;
  const SHA3_BLOCK_SIZE    = 72;

  const XSALSA20_IV_SIZE  = 24;
  const XSALSA20_KEY_SIZE = 32;
  const TWOFISH_IV_SIZE   = 16;
  CONST TWOFISH_KEY_SIZE  = 32;
  CONST AES_IV_SIZE       = 16;
  const AES_KEY_SIZE      = 32;

  // order is important!
  protected static $keySizes = [
    'sha512'   => self::SHA512_KEY_SIZE,
    'sha3'     => self::SHA3_KEY_SIZE,
    'aes'      => self::AES_KEY_SIZE,
    'twofish'  => self::TWOFISH_KEY_SIZE,
    'xsalsa20' => self::XSALSA20_KEY_SIZE,
  ];

  protected static function compare($str1, $str2)
  {
    return hash_equals($str1, $str2);
  }

  protected static function hmac(string $data, string $key, callable $algoFn, int $algoBlockSizeInBytes): string
  {
    if (strlen($key) > $algoBlockSizeInBytes)
    {
      $key = $algoFn($key); // keys longer than blocksize are shortened
    }

    if (strlen($key) < $algoBlockSizeInBytes)
    {
      $key = $key . str_repeat(chr(0x00), $algoBlockSizeInBytes - strlen($key)); // keys shorter than blocksize are zero-padded
    }

    $outerKeyPad = str_repeat(chr(0x5c), $algoBlockSizeInBytes) ^ $key;
    $innerKeyPad = str_repeat(chr(0x36), $algoBlockSizeInBytes) ^ $key;

    return $algoFn($outerKeyPad . $algoFn($innerKeyPad . $data));
  }

  protected static function sha512hmac($data, $key)
  {
    $hashFn = function ($data) { return hash('sha512', $data, true); };
    return static::hmac($data, $key, $hashFn, static::SHA512_BLOCK_SIZE);
  }

  protected static function sha3hmac($data, $key)
  {
    $hashFn = function ($data) { return bb\Sha3\Sha3::hash($data, 512, true); };
    return static::hmac($data, $key, $hashFn, static::SHA3_BLOCK_SIZE);
  }

  protected static function getRandomBytes($numBytes)
  {
    return \Sodium\randombytes_buf($numBytes);
  }

  protected static function xsalsa20Encrypt($str, $key)
  {
    $iv = static::getRandomBytes(static::XSALSA20_IV_SIZE);
    return $iv . \Sodium\crypto_stream_xor($str, $iv, $key);
  }

  protected static function xsalsa20Decrypt($str, $key)
  {
    $iv  = substr($str, 0, static::XSALSA20_IV_SIZE);
    $str = substr($str, static::XSALSA20_IV_SIZE);
    return \Sodium\crypto_stream_xor($str, $iv, $key);
  }

  protected static function twofishEncrypt($str, $key)
  {
    $iv = static::getRandomBytes(static::TWOFISH_IV_SIZE);
    return $iv . mcrypt_encrypt(MCRYPT_TWOFISH, $key, $str, 'ctr', $iv);
  }

  protected static function twofishDecrypt($str, $key)
  {
    $iv  = substr($str, 0, static::TWOFISH_IV_SIZE);
    $str = substr($str, static::TWOFISH_IV_SIZE);
    return mcrypt_decrypt(MCRYPT_TWOFISH, $key, $str, 'ctr', $iv);
  }

  protected static function aesEncrypt($str, $key)
  {
    $iv = static::getRandomBytes(static::AES_IV_SIZE);
    return $iv . mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $str, 'ctr', $iv);
  }

  protected static function aesDecrypt($str, $key)
  {
    $iv  = substr($str, 0, static::AES_IV_SIZE);
    $str = substr($str, static::AES_IV_SIZE);
    return mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $str, 'ctr', $iv);
  }

  protected function getStretchedKeys($key, $salt)
  {
    $totalSize   = array_sum(static::$keySizes);
    $keyMaterial = hex2bin(scrypt($key, $salt, static::SCRYPT_N, static::SCRYPT_R, static::SCRYPT_P, $totalSize));
    if (strlen($keyMaterial) != $totalSize)
    {
      throw new RuntimeException('scrypt returned the wrong number of bytes');
    }

    $keys = [];
    foreach (static::$keySizes as $algo => $keySize)
    {
      $keys[$algo] = substr($keyMaterial, 0, $keySize);
      $keyMaterial = substr($keyMaterial, $keySize);
    }
    return $keys;
  }

  public static function encrypt($plaintext, $initialKey)
  {
    $salt = static::getRandomBytes(static::SALT_LENGTH);
    $keys = static::getStretchedKeys($initialKey, $salt);

    $header    = join('', array_map('chr', array_merge(static::MAGIC_BYTES, static::VERSION)));
    $encrypted =
      static::aesEncrypt(static::twofishEncrypt(static::xsalsa20Encrypt($plaintext, $keys['xsalsa20']), $keys['twofish']), $keys['aes']);

    $toMac = $header . $salt . $encrypted;
    $mac1  = static::sha512hmac($toMac, $keys['sha512']);
    $mac2  = static::sha3hmac($toMac, $keys['sha3']);

    return bin2hex($header . $salt . $mac1 . $mac2 . $encrypted);
  }

  public static function decrypt($ciphertext, $initialKey)
  {
    $ciphertext = hex2bin($ciphertext);

    $header = join('', array_map('chr', array_merge(static::MAGIC_BYTES, static::VERSION)));

    $minLength = strlen($header) + static::SALT_LENGTH + static::SHA512_OUTPUT_SIZE + static::SHA3_OUTPUT_SIZE +
                 static::XSALSA20_IV_SIZE + static::TWOFISH_IV_SIZE + static::AES_IV_SIZE;

    if (strlen($ciphertext) < $minLength)
    {
      throw new Exception('input is too short');
    }

    if (substr($ciphertext, 0, strlen($header)) !== $header)
    {
      throw new Exception('invalid magic byte or version');
    }
    $ciphertext = substr($ciphertext, strlen($header));

    $salt       = substr($ciphertext, 0, static::SALT_LENGTH);
    $ciphertext = substr($ciphertext, static::SALT_LENGTH);

    $keys = static::getStretchedKeys($initialKey, $salt);

    $mac1       = substr($ciphertext, 0, static::SHA512_OUTPUT_SIZE);
    $ciphertext = substr($ciphertext, static::SHA512_OUTPUT_SIZE);

    $mac2       = substr($ciphertext, 0, static::SHA3_OUTPUT_SIZE);
    $ciphertext = substr($ciphertext, static::SHA3_OUTPUT_SIZE);

    $toMac = $header . $salt . $ciphertext;
    if (!static::compare($mac1, static::sha512hmac($toMac, $keys['sha512'])))
    {
      throw new Exception('sha512 hmac does not match');
    }
    if (!static::compare($mac2, static::sha3hmac($toMac, $keys['sha3'])))
    {
      throw new Exception('sha3 hmac does not match');
    }

    return static::xsalsa20Decrypt(static::twofishDecrypt(static::aesDecrypt($ciphertext, $keys['aes']), $keys['twofish']),
      $keys['xsalsa20']);
  }
}
