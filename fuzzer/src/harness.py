
from asyncio.subprocess import PIPE
import datetime
import os
from queue import Empty, Full, Queue
import subprocess
import sys
from threading import Semaphore, Thread, active_count, enumerate, current_thread, main_thread
import time
import re
import signal

from utils import Fuzz

class Harness():

    def __init__(self, program: str, seed: str, fuzzer: Fuzz) -> None:

        self.program = program
        self.seed = seed
        self.fuzzer = fuzzer

        self.QUEUE_SIZE = 1000
        self.MAX_TESTS = 1000000000
        self.TESTERS = 20
        self.FUZZERS = 1
        self.LOGFILE = open('log.out', 'w')

        self.queue = Queue(maxsize=self.QUEUE_SIZE)
        self.counter = 0
        self.c_semaphore = Semaphore()

        self.crashes = 0
        self.crashes_semaphore = Semaphore()

        self.isStarted = False
        self.s_semaphore = Semaphore()

        self.success = False
        self.success_semaphore = Semaphore()

        self.out_semaphore = Semaphore()
        self.outfile = open('bad.txt', 'w')

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
        t = current_thread()
        t.alive = True
        while t.alive == True and self.success == False:
            try:
                fuzzInput = self.queue.get(timeout=0.2)
            except Empty:
                pass
            else:
                try:
                    self.c_semaphore.acquire()
                    self.counter += 1
                    self.c_semaphore.release()
                    with subprocess.Popen(["gdb", self.program, "--command=harness.gdb"], input=fuzzInput, check=True, stdout=PIPE, text=True) as process:
                        print(process.pid)
                    
                    self.LOGFILE.write(fuzzInput+'\n...\n')
                except subprocess.CalledProcessError as e:
                    if e.returncode != -2:
                        self.out_semaphore.acquire()
                        self.outfile.write(fuzzInput + '\n')
                        self.success_semaphore.acquire()
                        self.success = True
                        self.success_semaphore.release()
                else:
                    pass

        


    def fuzz(self) -> None:
        """
        Fuzzer function generates mutations and places mutations on to the queue
        """
        t = current_thread()
        t.alive = True
        for _ in range(self.MAX_TESTS):
            if t.alive == True:
                '''
                # Legit input to valid that no segfault occurs initially before fuzzer output used
                for i in range(10000):
                    try:
                        self.queue.put(r'{"len": 12, "input": "AAAABBBBCCCC", "more_data": ["a", "bb"]}')                    
                    except Full:
                        pass
                '''
                try:
                    input = self.fuzzer.fuzz()
                    if input != None:
                        self.queue.put(self.fuzzer.fuzz())          
                except Full:
                    pass
            else:
                sys.exit(0)


    def finish(self):
        print('Closing threads...')
        for t in enumerate():
            t.alive = False
        time.sleep(3)
        self.LOGFILE.close()
        self.outfile.close()
        print('Output saved to bad.txt')  


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
        try:
            start = time.time()
            while time.time() < start + 190:
                if prev_time != 0 and self.success == False:

                    # Create the table

                    table = {
                        "Binary Name":self.program,
                        "Run Time":total_time,
                        "Total Tests":curr_count,
                        "Queue Length":self.queue.qsize(),
                        "Current Rate":curr_rate,
                        "Overall Rate":total_rate,
                        "Total Crashes":self.crashes,
                    }
                    
                    table_format = "{:<15}" * (len(table.keys()) + 1)

                    # Print output
                    if sys.platform == 'linux' or sys.platform == 'darwin':
                        os.system("clear")
                    elif sys.platform == 'win32':
                        os.system("cls")

                    # Update variables
                    curr_time = time.time()
                    curr_count = self.counter
                    total_time = str(datetime.timedelta(seconds = round(curr_time - start_time)))
                    curr_rate = round((curr_count-prev_count)/(curr_time - prev_time))
                    total_rate = round(curr_count/(curr_time - start_time))

                    print(table_format.format("", *table.keys())) # Prints the headers
                    print(table_format.format("", *table.values())) # Prints the values
                    print("Press Ctrl + C to exit.")

                elif self.success == True:
                    print('Success!')
                    self.finish()
                    return

                prev_time = curr_time
                prev_count = curr_count
                time.sleep(refresh_time)

        except KeyboardInterrupt: # Ctrl + C
            print('Received Ctrl + C')
            self.finish()
            return

        print('Times Up!')
        self.finish()
        return


if __name__ == '__main__':
    try:
        inputs = [
            'header,must,stay,intact',
            '0,1,1,0'
        ]
        s = subprocess.run('tests/csv1', input='\n'.join(inputs), check=True, text=True)
        print(s.returncode)
    except subprocess.CalledProcessError as e:
        print(e.args, e.returncode)