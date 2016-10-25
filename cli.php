#!/usr/bin/php
<?php

require_once __DIR__.'/Triplesec.class.php';

function usage()
{
  echo "Usage: php " . basename($_SERVER['argv'][0]) . " enc|dec TEXT KEY\n";
}


$args = $_SERVER['argv'];

if (count($args) != 4)
{
  usage();
  exit(1);
}

list($binary, $command, $text, $key) = $args;
$command = strtolower($command);

try 
{
  if ($command == 'enc')
  {
    echo TripleSec::encrypt($text, $key);
  }
  elseif ($command == 'dec')
  {
    echo TripleSec::decrypt($text, $key);
  }
  else
  {
    usage();
    exit(1);
  }  
}
catch (TripleSecInvalidKeyException $e)
{
  echo "Error: Invalid key\n";
  exit(1);
}