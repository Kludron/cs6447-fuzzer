
import datetime
import os
from queue import Empty, Full, Queue
import random
import string
import subprocess
import sys
from threading import Semaphore, Thread
import time

from prettytable import PrettyTable

class Harness():

    def __init__(self, program, seed) -> None:

        self.program = program
        self.seed = seed

        self.QUEUE_SIZE = 1000
        self.MAX_TESTS = 1000000000
        self.TESTERS = 20
        self.FUZZERS = 1
        self.LOGFILE = open('log.out', 'a')

        self.queue = Queue(maxsize=self.QUEUE_SIZE)
        self.counter = 0
        self.c_semaphore = Semaphore()

        self.isStarted = False
        self.s_semaphore = Semaphore()

    def start(self) -> None:
        # Check if the harness has already been started
        self.s_semaphore.acquire()
        if self.isStarted: return
        else: self.isStarted = True
        self.s_semaphore.release()

        if not os.path.isfile(self.program):
            print('Binary not found')
            raise Exception(f'Binary file {self.program} not found')
        elif not os.path.isfile(self.seed):
            print('Seed not found')
            raise Exception(f'Seed file {self.seed} not found')
        else:
            # Create and start tester threads
            for i in range(self.TESTERS):
                thread = Thread(target=self.test, daemon=True)
                thread.start()

            # Create and start fuzzer threads
            for i in range(self.FUZZERS):
                thread = Thread(target=self.fuzz, daemon=True)
                thread.start()

    def __randomword(self, length) -> str:
        """
        Random string generator to act as a simple fuzzer engine
        Can be removed when we have fuzzer engines for the different
        file formats.
        """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(length))

    def test(self):
        while True:
            try:
                fuzz = self.queue.get(timeout=0.2)
            except Empty:
                pass
            else:
                try:
                    # print("This is run", self.counter)
                    self.c_semaphore.acquire()
                    self.counter += 1
                    self.c_semaphore.release()
                    subprocess.run(self.program, input=fuzz, check=True, text=True, stdout=self.LOGFILE)
                except subprocess.CalledProcessError:
                    #######################################
                    #Update this to record input that crashes binary and exit fuzzer
                    #######################################
                    pass
                else:
                    pass

    def fuzz(self) -> None:
        """
        Fuzzer function generates mutations and places mutations on to the queue
        """
        # for i in range(self.max_tests):
        #     try:
        #         #Replace this with fuzzer content generation
        #         string = self.__randomword(8)
        #         self.queue.put(string)
        #     except Full:
        #         pass

        count = 1
        while count < self.MAX_TESTS:
            try:
                #Replace this with fuzzer content generation
                string = self.__randomword(8)
                self.queue.put(string)
            except Full:
                pass
            else:
                count += 1

    def monitor(self, refresh_time=2) -> None:
        self.start()

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
                    self.program,
                    total_time,
                    self.counter,
                    self.queue.qsize(),
                    curr_rate,
                    total_rate
                ])

                # Update variables
                curr_time = time.time()
                # curr_count = self.counter
                total_time = str(datetime.timedelta(seconds = round(curr_time - start_time)))
                curr_rate = round((curr_count-prev_count)/(curr_time - prev_time))
                total_rate = round(curr_count/(curr_time - start_time))

                # Print output
                if sys.platform == 'linux' or sys.platform == 'darwin':
                    os.system("clear")
                elif sys.platform == 'win32':
                    os.system("cls")
                print(table)
            prev_time = curr_time
            prev_count = curr_count
            time.sleep(refresh_time)