use inc::Module::Install;
use Module::Install::AuthorTests;

name 'Amon2-Auth-Site-Mixi';
all_from 'lib/Amon2/Auth/Site/Mixi.pm';

requires 'Amon2::Auth' => '0.01';
requires 'Mouse' => '0.97';
requires 'LWP' => '6.00';
requires 'URI' => '1.54';
requires 'JSON' => '2.53';

tests 't/*.t';
author_tests 'xt';

tests 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t';
test_requires 'Test::More' => 0.96;
WriteAll;
