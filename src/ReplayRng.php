<?php

namespace lyoshenka;

/**
 * Class ReplayRng
 * @package lyoshenka
 *
 * Returns preset bytes. Useful for testing things that are normally random.
 *
 * ONLY USE THIS FOR TESTING
 *
 */
class ReplayRng implements RngInterface
{
  protected $randomBytes;

  public function __construct(string $randomBytes)
  {
    $this->randomBytes = $randomBytes;
  }

  public function getRandomBytes(int $numBytes): string
  {
    if ($numBytes > strlen($this->randomBytes))
    {
      throw new \UnderflowException('Not enough random bytes');
    }

    $return = substr($this->randomBytes, 0, $numBytes);
    $this->randomBytes = substr($this->randomBytes, $numBytes);

    return $return;
  }
}