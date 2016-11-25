## php-triplesec

PHP implementation of [Triplesec](https://keybase.io/triplesec).


## Installation

### Requirements

- php7+
- extensions: mcrypt, scrypt, libsodium

On Ubuntu 16.04:

    sudo apt install build-essential php7.0 php7.0-dev php7.0-mcrypt php-pear libsodium18 libsodium-dev
    sudo pecl install libsodium scrypt
    echo 'extension=libsodium.so' | sudo tee /etc/php/7.0/mods-available/libsodium.ini
    echo 'extension=scrypt.so' | sudo tee /etc/php/7.0/mods-available/scrypt.ini
    sudo phpenmod libsodium scrypt

### Composer Install

    composer install lyoshenka/php-triplesec

## Usage

    <?php
    
    require __DIR__.'/vendor/autoload.php';
    
    echo \lyoshenka\TripleSec::encrypt('this is the secret message', 's3cr3tk3y') . "\n";
    
## Tests

    php test/test.php