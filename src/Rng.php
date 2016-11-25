<?php

namespace lyoshenka;

class Rng implements RngInterface
{
  public function getRandomBytes(int $numBytes): string
  {
    return random_bytes($numBytes);
  }
}