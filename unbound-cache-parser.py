#!/usr/bin/env python3

import getopt
import itertools
import pickle
import re
import sys

class DNS_Record_Printer:
    def _print_record(self, record):
        raise NotImplementedError("Please implement this yourself.")

    def print_records(self, records):
        for record in records:
            line = self._print_record(record)
            if line:
                print(line)

class Hosts_Printer(DNS_Record_Printer):
    def _print_record(self, record):
        if record.rtype != 'A' and record.rtype != 'AAAA':
            return None

        return record.rdata + '\t' + record.rname[:-1]

class Unbound_Control_Local_Printer(DNS_Record_Printer):
    def _print_record(self, record):
        return 'unbound-control local_data \"' + record.rname + ' ' + record.rclass + ' ' + record.rtype + ' ' + record.rdata + '\"' 

class Unbound_Control_Local_Remove_Printer(DNS_Record_Printer):
    def _print_record(self, record):
        return 'unbound-control local_data_remove \"' + record.rname + '\"' 

class Unbound_Cache_Printer(DNS_Record_Printer):
    def print_records(self, records):
        print('START_RRSET_CACHE')
        for record in records:
            line = self._print_record(record)
            if line:
                print(line)
        print('END_RRSET_CACHE')
        print('START_MSG_CACHE')
        print('END_MSG_CACHE')
        print('EOF')

    def _print_record(self, record):
        return record.rname + '\t3600\t' + record.rclass + '\t' + record.rtype + '\t' + record.rdata

class DNS_Record_Filter:
    def filter(self, record):
        raise NotImplementedError("Please implement this yourself.")

class No_Filter(DNS_Record_Filter):
    def filter(self, record):
        return True

class Type_Filter(DNS_Record_Filter):
    def __init__(self, rtype):
        self.__rtype = rtype

    def filter(self, record):
        return record.rtype == self.__rtype

class Name_Regex_Filter(DNS_Record_Filter):
    def __init__(self, regex):
        self.__regex = re.compile(regex)

    def filter(self, record):
        return self.__regex.match(record.rname)

class IP_Regex_Filter(DNS_Record_Filter):
    def __init__(self, regex):
        self.__regex = re.compile(regex)

    def filter(self, record):
        if record.rtype == 'A' or record.rtype == 'AAAA':
            return self.__regex.match(record.rdata)

        return False

class AND_Filter(DNS_Record_Filter):
    def __init__(self, filters):
        self.__filters = filters

    def filter(self, record):
        return all(f.filter(record) for f in self.__filters)

class OR_Filter(DNS_Record_Filter):
    def __init__(self, filters):
        self.__filters = filters

    def filter(self, record):
        return any(f.filter(record) for f in self.__filters)

class NOT_Filter(DNS_Record_Filter):
    def __init__(self, f):
        self.__filter = f

    def filter(self, record):
        return not self.__filter.filter(record)

class DNS_Cache:
    def __init__(self):
        self.__records = dict()

    def add_record(self, record):
        if record.rname not in self.__records:
            self.__records[record.rname] = list()
        self.__records[record.rname].append(record)

    def records(self):
        return flatten_dict(self.__records)

    def merge(self, cache):
        merged = DNS_Cache()
        merged.__records = self.__records.copy()
        merged.__records.update(cache.__records)

        return merged

    def filter(self, record_filter):
        cache = DNS_Cache()

        for record in flatten_dict(self.__records):
            if record_filter.filter(record):
                cache.add_record(record)

        return cache

    def save(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self, f)

    @staticmethod
    def load(filename):
        with open(filename, 'rb') as f:
            return pickle.load(f)

    @staticmethod
    def read(f):
        cache = DNS_Cache()

        next(f)
        for l in f:
            line = l.strip()

            if line == 'END_RRSET_CACHE':
                break
            if line[0] == ';':
                continue

            data = line.split(maxsplit = 4)
            record = DNS_Record(data[0], data[3], data[2], data[4])

            cache.add_record(record)

        return cache

class DNS_Record:
    def __init__(self, rname, rtype, rclass, rdata):
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.rdata = rdata

def flatten_dict(dict_lists):
    return itertools.chain(*dict_lists.values())

def usage():
    print("""USAGE: %s [options]
            -l The saved cache to load (optional).
            -s The file where the (filtered) cache is stored (optional).
            -r If present a cache is read from STDIN.
               If '-l' is also used the caches are merged. Data from STDIN is considered to be more recent.
            -p The format used to print out the (filtered) cache. One of %s.
            -f A filter specification of the form <filter name>[:<filter args>]. The following filters are allowed: %s.
               'type' takes a record type as argument.
               'name' takes a regular expression for the domain name as argument.
               'ip' takes a regular expression for the IP address as argument.
               The binary operators 'and' and 'or' and the unary 'not' are applied by specifying multiple '-f' options in RPN order.
            -h This help text.""" %
            ( sys.argv[0],
              list(PRINTERS.keys()),
              list(FILTERS.keys())
            )
         )
    sys.exit(1)

class Options:
    load_file = None
    save_file = None
    read_from_stdin = False
    printer = None
    filter_a = No_Filter()
    filter_b = None

options = Options()

PRINTERS = { 'hosts': lambda: Hosts_Printer(),
             'unbound_local': lambda: Unbound_Control_Local_Printer(),
             'unbound_local_remove': lambda: Unbound_Control_Local_Remove_Printer(),
             'unbound_cache': lambda: Unbound_Cache_Printer()
           }

FILTERS = { 'type': lambda t: Type_Filter(t),
            'name': lambda r: Name_Regex_Filter(r),
            'ip': lambda r: IP_Regex_Filter(r),
            'and': lambda o: AND_Filter([o[0], o[1]]),
            'or': lambda o: OR_Filter([o[0], o[1]]),
            'not': lambda o: NOT_Filter(o)
          }

def parse_filters(filter_str, options):
    fs = filter_str.split(":", maxsplit = 1)

    filter_name = fs[0]

    if filter_name not in FILTERS:
        usage()

    if filter_name == 'type' or filter_name == 'name' or filter_name == 'ip':
        if len(fs) < 2:
            usage()
        if options.filter_b:
            usage()
        if not options.filter_a or type(options.filter_a) is No_Filter:
            options.filter_a = FILTERS[filter_name](fs[1])
        else:
            options.filter_b = FILTERS[filter_name](fs[1])

    elif filter_name == 'and' or filter_name == 'or':
        if len(fs) > 1:
            usage()
        if not options.filter_a or not options.filter_b:
            usage()
        options.filter_a = FILTERS[filter_name]((options.filter_a, options.filter_b))
        options.filter_b = None

    else:
        if len(fs) > 1:
            usage()
        if options.filter_b:
            usage()
        options.filter_a = FILTERS[filter_name](options.filter_a)

if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "l:s:rp:f:h")
    for o, a in opts:
        if o == '-l':
            options.load_file = a
        elif o == '-s':
            options.save_file = a
        elif o == '-r':
            options.read_from_stdin = True
        elif o == '-p':
            if a not in PRINTERS:
                usage()
            options.printer = PRINTERS[a]()
        elif o == '-f':
            parse_filters(a, options)
        else:
            usage()

    if options.filter_b:
        usage()

    cache_l = DNS_Cache()
    cache_r = DNS_Cache()

    if options.load_file:
        cache_l = DNS_Cache.load(options.load_file)

    if options.read_from_stdin:
        cache_r = DNS_Cache.read(sys.stdin)

    cache_w = cache_l.merge(cache_r)

    cache_f = cache_w.filter(options.filter_a)

    if options.save_file:
        cache_f.save(options.save_file)

    if options.printer:
        options.printer.print_records(cache_f.records())
