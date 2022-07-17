#!/usr/bin/env python3

# COMP6447 Fuzzer

from utils import *
from harness import Harness
import sys

TESTBINARY='tests/csv1'
TESTSEED='tests/csv1.txt'

def print_type(file):
    val = checkType(file)
    if val == TYPE_FAIL:
        print("Failed to open file/detect input type")
    elif val == TYPE_CSV:
        print("Detected CSV")
    elif val == TYPE_JSON:
        print("Detected JSON")
    elif val == TYPE_XML:
        print("Detected XML")
    elif val == TYPE_PLAINTEXT:
        print("Detected Plaintext")
    elif val == TYPE_JPG:
        print("Detected JPG")

# getType returns the data from the seed file. Update functions to read the data passed through, rather than the seed file to save from re-opening the seed file.
def run(program, seed):
    print_type(seed)
    fuzzer = getType(seed)
    if not fuzzer == TYPE_FAIL:
        harness = Harness(program, seed, fuzzer)
        harness.monitor()
    else:
        print('Failed to open or detect seed type.')

if __name__ == '__main__':
    argc = len(sys.argv)
    if argc < 3:
        usage = f"{sys.argv[0]} <binary file> <seed file>"
        print(usage)
    else:
        run(sys.argv[1], sys.argv[2])
