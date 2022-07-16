
import datetime
import os
from queue import Empty, Full, Queue
import subprocess
import sys
from threading import Semaphore, Thread
import time

from utils import Fuzz

class Harness():

    def __init__(self, program: str, seed: str, fuzzer: Fuzz) -> None:

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

        self.fuzzer = fuzzer

    def start(self) -> None:
        # Check if the harness has already been started
        self.s_semaphore.acquire()
        if self.isStarted: return
        else: self.isStarted = True
        self.s_semaphore.release()

        # Ensure given files are valid
        if not os.path.isfile(self.program):
            print('Binary not found')
            raise Exception(f'Binary file {self.program} not found')
        elif not os.path.isfile(self.seed):
            print('Seed not found')
            raise Exception(f'Seed file {self.seed} not found')
        else:
            # Create and start tester threads
            for _ in range(self.TESTERS):
                thread = Thread(target=self.test, daemon=True)
                thread.start()

            # Create and start fuzzer threads
            for _ in range(self.FUZZERS):
                thread = Thread(target=self.fuzz, daemon=True)
                thread.start()

    def test(self):
        while True:
            try:
                fuzzInput = self.queue.get(timeout=0.2)
            except Empty:
                pass
            else:
                try:
                    self.c_semaphore.acquire()
                    self.counter += 1
                    self.c_semaphore.release()
                    subprocess.run(self.program, input=fuzzInput, check=True, text=True, stdout=self.LOGFILE)
                except subprocess.CalledProcessError:
                    #######################################
                    # Update this to record input that crashes binary and exit fuzzer
                    #######################################
                    pass
                else:
                    pass

    def fuzz(self) -> None:
        """
        Fuzzer function generates mutations and places mutations on to the queue
        """
        for _ in range(self.MAX_TESTS):
            try:
                # Replace this with fuzzer content generation
                self.queue.put(self.fuzzer.fuzz())
            except Full:
                pass

    def monitor(self, refresh_time=2) -> None:
        self.start()

        # Set defaults
        curr_count = self.counter
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

                table = {
                    "Binary Name":self.program,
                    "Run Time":total_time,
                    "Total Tests":curr_count,
                    "Queue Length":self.queue.qsize(),
                    "Current Rate":curr_rate,
                    "Overall Rate":total_rate,
                }
                
                table_format = "{:<15}" * (len(table.keys()) + 1)

                # Print output
                if sys.platform == 'linux' or sys.platform == 'darwin':
                    os.system("clear")
                elif sys.platform == 'win32':
                    os.system("cls")

                print(table_format.format("", *table.keys())) # Prints the headers
                print(table_format.format("", *table.values())) # Prints the values

                # Update variables
                curr_time = time.time()
                curr_count = self.counter
                total_time = str(datetime.timedelta(seconds = round(curr_time - start_time)))
                curr_rate = round((curr_count-prev_count)/(curr_time - prev_time))
                total_rate = round(curr_count/(curr_time - start_time))

            prev_time = curr_time
            prev_count = curr_count
            time.sleep(refresh_time)