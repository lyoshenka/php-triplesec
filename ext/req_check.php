<?php

foreach (['libsodium', 'scrypt', 'mcrypt'] as $extension)
{
  if (!extension_loaded($extension))
  {
    throw new RuntimeException($extension . ' extension required');
  }
}
