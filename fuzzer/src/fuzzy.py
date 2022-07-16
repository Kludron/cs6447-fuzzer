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
import os

from prettytable import PrettyTable

QUEUE_SIZE = 1000
MAX_TESTS = 1000000000
TESTERS = 20
FUZZERS = 1
LOGFILE = open('log.out', 'a')

q1 = queue.Queue(maxsize=QUEUE_SIZE)
counter = 0
counter_semaphore = threading.Semaphore()


def randomword(length):
    """
    Random string generator to act as a simple fuzzer engine
    Can be removed when we have fuzzer engines for the different
    file formats."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def test(tester, program:str):
    """
    Tester function takes mutations from queue and runs them again binary.
    """
    global counter
    while True:
        try:
            fuzz = q1.get()
        except queue.Empty:
            pass
        else:
            try:
                counter_semaphore.acquire()
                counter += 1
                counter_semaphore.release()
                subprocess.run(program, input=fuzz, check=True, text=True, stdout=LOGFILE)
            #Perform basic exit code monitoring of binary
            except subprocess.CalledProcessError:
                #######################################
                #Update this to record input that crashes binary and exit fuzzer
                #######################################
                pass
            else:
                pass

def fuzz(generator, seed):
    """
    Fuzzer function generates mutations and places mutations on to the queue
    """
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

def monitor(refresh_time=2):
    # Set defaults
    curr_count = 0
    prev_count = 0
    start_time = time.time()
    curr_time = start_time
    prev_time = 0
    curr_rate = 0
    total_rate = 0
    total_time = str(datetime.timedelta(seconds = round(curr_time - start_time)))

    # Start monitoring loop
    while True:
        if prev_time != 0:
            # Create the table
            table = PrettyTable([
                "Binary Name",
                "Run Time",
                "Total Tests",
                "Queue Length",
                "Current Rate",
                "Overall Rate"
            ])
            table.add_row([
                program,
                total_time,
                curr_count,
                q1.qsize(),
                curr_rate,
                total_rate
            ])

            # Update variables
            curr_time = time.time()
            curr_count = counter
            total_time = str(datetime.timedelta(seconds = round(curr_time - start_time)))
            curr_rate = round((curr_count-prev_count)/(curr_time - prev_time))
            total_rate = round(curr_count/(curr_time - start_time))
            
            # Print to screen
            if sys.platform == 'linux' or sys.platform == 'darwin':
                os.system("clear")
            elif sys.platform == 'win32':
                os.system("cls")
            print(table)

        prev_time = curr_time
        prev_count = curr_count
        time.sleep(refresh_time)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"usage: ./{sys.argv[0]} <binary name> <seed file>")
        quit()

    program = sys.argv[1]
    seed = sys.argv[2]

    if os.path.isfile(program) == False:
        print(f"Binary {program} not found")
        quit()
    if os.path.isfile(seed) == False:
        print(f"Seed file {seed} not found")
        quit()

    # Create testers threads
    for i in range(TESTERS):
        x = threading.Thread(target=test, daemon=True, args=(i, program))
        x.start()

    # Create fuzzer threads
    for i in range(FUZZERS):
        x = threading.Thread(target=fuzz, daemon=True, args=(i, seed))
        x.start()

    #Create monitoring output
    monitor()

    # curr_count = 0
    # prev_count = 0
    # start_time = time.time()
    # curr_time = start_time
    # prev_time = 0
    # curr_rate = 0
    # total_rate = 0
    # total_time = 0
    # os.system("clear")
    # print(f"""
    # {'Binary Name:'  : <17}{program}
    # {'Run time:'     : <16}{'0:00:00' : >8}
    # {'Total tests:'  : <16}{curr_count : >8}
    # {'Queue Length:' : <16}{q1.qsize() : >8}
    # {'Current Rate:' : <16}{curr_rate : >8} tests/sec
    # {'Overall Rate:' : <16}{total_rate : >8} tests/sec
    # """)
    # # print(  f"{'Binary Name:' : <17}{program}\n"
    # #         f"{'Run time:' : <16}{'0:00:00' : >8}\n"
    # #         f"{'Total tests:' : <16}{curr_count : >8}\n"
    # #         f"{'Queue Length:' : <16}{q1.qsize() : >8}\n"
    # #         f"{'Current Rate:' : <16}{curr_rate : >8} tests/sec\n"
    # #         f"{'Overall Rate:' : <16}{total_rate : >8} tests/sec")
    # while True:
    #     if prev_time != 0:
    #         curr_time = time.time()
    #         curr_count = counter
    #         total_time = str(datetime.timedelta(seconds = round(curr_time - start_time)))
    #         curr_rate = round((curr_count-prev_count)/(curr_time - prev_time))
    #         total_rate = round(curr_count/(curr_time - start_time))
    #         os.system("clear")
    #         print(  f"{'Binary Name:' : <17}{program}\n"
    #                 f"{'Run time:' : <16}{total_time : >8}\n"
    #                 f"{'Total tests:' : <16}{curr_count : >8}\n"
    #                 f"{'Queue Length:' : <16}{q1.qsize() : >8}\n"
    #                 f"{'Current Rate:' : <16}{curr_rate : >8} tests/sec\n"
    #                 f"{'Overall Rate:' : <16}{total_rate : >8} tests/sec")
    #     prev_time = curr_time
    #     prev_count = curr_count
    #     time.sleep(1)




