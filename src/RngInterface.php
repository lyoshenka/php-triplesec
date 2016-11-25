<?php

namespace lyoshenka;

interface RngInterface
{
  public function getRandomBytes(int $numBytes): string;
}