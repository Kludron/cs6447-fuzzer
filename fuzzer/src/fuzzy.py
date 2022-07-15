#!/bin/python3

import random
import string
import queue
import threading
import time
import sys
import os.path
import subprocess
import datetime

QUEUE_SIZE = 1000
MAX_TESTS = 1000000000
TESTERS = 20
FUZZERS = 1


q1 = queue.Queue(maxsize=QUEUE_SIZE)
counter = 0
count_sem = threading.Semaphore()


def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))


def test(tester, program):
    global counter
    while True:

        try:
            fuzz = q1.get()
        except queue.Empty:
            pass
        else:
            try:
                count_sem.acquire()
                counter += 1
                count_sem.release()
                subprocess.run(program, input=fuzz, check=True, text=True)
            except subprocess.CalledProcessError:
                #Update this to record input and stop
                pass
            else:
                pass


def fuzz(generator, seed):
    count = 1
    while count < MAX_TESTS:
        try:
            #Replace this with fuzzer content generation
            string = randomword(8)
            q1.put(string)
        except queue.Full:
            pass
        else:
            count += 1

 
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("usage: ./fuzzy.py <binary name> <seed file>")
        quit()

    program = sys.argv[1]
    seed = sys.argv[2]

    if os.path.isfile(program) == False:
        print(f"Binary {program} not found")
        quit()
    if os.path.isfile(seed) == False:
        print(f"Seed fie {seed} not found")
        quit()

    # Create testers
    for i in range(TESTERS):
        x = threading.Thread(target=test, daemon=True, args=(i, program))
        x.start()

    # Create fuzzer
    for i in range(FUZZERS):
        x = threading.Thread(target=fuzz, daemon=True, args=(i, seed))
        x.start()

    curr_count = 0
    prev_count = 0
    start_time = time.time()
    curr_time = start_time
    prev_time = 0
    curr_rate = 0
    while True:
        if prev_time != 0:
            curr_time = time.time()
            curr_count = counter
            total_time = datetime.timedelta(seconds =round(curr_time - start_time))
            curr_rate = round((curr_count-prev_count)/(curr_time - prev_time))
            total_rate = round(curr_count/(curr_time - start_time))
            print(f"Running: {total_time}\nTests: {curr_count}\nQueue Length: {q1.qsize()}\nRecent Rate: {curr_rate}/sec\nOverall Rate: {total_rate}/sec\n----")
        prev_time = curr_time
        prev_count = curr_count
        time.sleep(10)




