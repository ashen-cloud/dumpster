#!/usr/bin/python3

import subprocess
import ctypes
import struct
import sys
import threading
import time
import os
import argparse
import binascii
import ast

from multiprocessing import Pool
from argparse import ArgumentParser

sys.set_int_max_str_digits(10000000)

parser = ArgumentParser()

parser.add_argument("-t", "--test", action=argparse.BooleanOptionalAction, help="Run memory dumping tests")
parser.add_argument('pid', nargs='?', help='Pid to dump')
parser.add_argument('-r', "--region", nargs='?', help='Memory region to dump (stack,heap,etc)')
parser.add_argument('-o', "--out", nargs='?', help='File to dump to')
parser.add_argument('-mb', "--match-bytes", nargs='?', help='Bytes to match')
parser.add_argument('-mi', "--match-int", nargs='?', help='Integers to match')

args = parser.parse_args()

region = args.region


def strbytes_to_bytes(st):  # todo: this is kinda sus
    res = b''
    a = st.split(' ')
    for strbyte in a:
        i = bytes.fromhex(strbyte)
        res += i
    return res


if os.geteuid() != 0:
    print('Run this with sudo instead')
    quit()


if not region:
    print('Memory region not specified, dumping the stack')
    region = 'stack'

if not args.test and not args.pid:
    print('Nothing to do')
    exit(1)


class Dumper:

    pid = None
    mem_file_path = None

    maps = []
    maps_raw = []

    def __init__(self, pid):
        self.pid = pid
        self.maps_file_path = f"/proc/{self.pid}/maps"
        self.mem_file_path = f"/proc/{self.pid}/mem"

    def read_maps(self, include_libs=True):

        with open(self.maps_file_path) as f:
            for line in f:
                parts = line.split()
                if not include_libs and len(parts) > 5:  # last item (6) is library name
                    continue
                addr_range = parts[0].split("-")
                start = int(addr_range[0], 16)
                end = int(addr_range[1], 16)
                self.maps_raw.append(line)
                self.maps.append((start, end))

            return self.maps, self.maps_raw  # maps is a list of tuples containing memory ranges in int format

    def read(self, address, length=4):  # for singular addresses
        try:
            with open(self.mem_file_path, 'rb') as f:
                f.seek(address)
                data = f.read(length)
                return data
        except OSError:
            return None

    def get_range(self, name):  # one of stack,heap,etc
        for line in self.maps_raw:
            rng = [l.replace(' ' * 7, '') for l in line.strip().split(' ' * 19)]
            if ('[' + name + ']') in ''.join(rng):
                return [int(el, 16) for el in rng[0].split(' ')[0].split('-')]  # [start address, end address]

    def dump_range(self, name, pagesize=4096, winsize=4, filter=False):
        start, end = self.get_range(name)
        memory = []
        indices = []
        for i in range(start, end, pagesize):
            res = self.read(i, pagesize)
            if filter and (res == (b'\x00' * pagesize)):
                continue
            for j in range(0, len(res), 4):
                window = res[j: j + winsize]
                if args.match_bytes is not None:
                    if window in strbytes_to_bytes(args.match_bytes):
                        memory.append(window)
                        indices.append(i)
                elif args.match_int is not None:
                    if int.from_bytes(window, 'little') == int(args.match_int):
                        memory.append(window)
                        indices.append(i)
                else:
                    memory.append(window)
                    indices.append(i)

        return memory, indices


address = None
pid = None


def run_read_test():
    global address, pid
    with subprocess.Popen(['./test/mem'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0) as r:
        for line in r.stdout:
            txt = line.strip()
            if 'Address' in txt:
                address = txt.split(' ')[1]
            if 'PID' in txt:
                pid = txt.split(' ')[1]
    return pid, address


def test_read():
    global address, pid

    def psearch(name):
        res = subprocess.check_output(['pgrep', name])
        return int(res.decode("utf-8").split('\n')[1])

    t = threading.Thread(target=run_read_test)
    t.daemon = True
    t.start()
    time.sleep(0.5)

    dumper = Dumper(pid)

    maps, raw_maps = dumper.read_maps()

    stack, stack_end = dumper.get_range('stack')

    address = int(address, 16)

    print('Testing address is within stack range')

    stack_len = len(range(stack, stack_end))
    address_index = range(stack, stack_end).index(address)
    assert stack_len > address_index

    print('Passed ✓')

    print('Testing stack extract')

    assert len(range(stack, stack_end)) == 135168

    print('Passed ✓')

    print('Testing stack read')

    res = dumper.read(address, 4)
    res_int = int.from_bytes(res, 'little')

    assert res_int == 1338

    print('Passed ✓')

    print('Testing heap read')

    heap_memory = dumper.dump_range('heap')

    found = False
    found_page = None
    found_window = None

    i = 0
    j = 0
    for page in heap_memory:
        for window in page:
            if window == b'9\x05\x00\x00':  # 1337 in python bytes
                found_page = i
                found_window = j
                found = True
            j += 1
        i += 1

    assert found is True
    assert found_page == 0
    assert found_window == 1196


if __name__ == '__main__':
    if args.test:
        test_read()
        quit()

    dumper = Dumper(args.pid)

    dumper.read_maps()

    memory, indices = dumper.dump_range(region)

    if args.out and args.out != '':
        print(f'Writing to {args.out}')
        try:
            os.remove(args.out)
        except Exception:
            pass
        with open(args.out, 'ab') as f:
            for window in memory:
                f.write(window)
    else:
        for x, z in zip(memory, indices):
            print(z, x)

