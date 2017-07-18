unbound-cache-parser
====================

A Python script for parsing, filtering, and printing data from the
[Unbound](https://unbound.net) DNS Server's cache (obtained by running
`unbound-control dump_cache`).

Usage
-----

unbound-cache-parser's default usage message:

    USAGE: ./unbound-cache-parser [options]
                -l The saved cache to load (optional).
                -s The file where the (filtered) cache is stored (optional).
                -r If present a cache is read from STDIN.
                   If '-l' is also used the caches are merged. Data from STDIN is
                   considered to be more recent.
                -p The format used to print out the (filtered) cache. One of ['hosts',
                   'unbound_cache', 'unbound_local', 'unbound_local_remove'].
                -f A filter specification of the form <filter name>[:<filter args>].
                   The following filters are allowed: ['not', 'name', 'and', 'type',
                   'ip', 'or'].
                   'type' takes a record type as argument.
                   'name' takes a regular expression for the domain name as argument.
                   'ip' takes a regular expression for the IP address as argument.
                   The binary operators 'and' and 'or' and the unary 'not' are applied
                   by specifying multiple '-f' options in RPN order.
                -h This help text.

Filters can be combined by specifying multiple `-f` options. For instance, to select
all records with the names "foo.example.com" and "bar.example.com" you have to use
`-f "name:^foo.example.com.$" -f "name:^bar.example.com.$" -f or`.

License
-------

unbound-cache-parser is licensed under the GPLv3.
