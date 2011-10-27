use inc::Module::Install;
name 'Amon2-Auth-Site-Mixi';
all_from 'lib/Amon2/Auth/Site/Mixi.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
