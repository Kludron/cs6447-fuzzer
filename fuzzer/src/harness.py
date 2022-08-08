
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
import enum

from utils import JSON_Fuzz
from utils import Fuzz
from gdb_harness import Gdb
from pygdbmi.gdbcontroller import GdbController

#BINARY RETURN CODES

class Error(enum.Enum):
    SIGHUP = -1
    SIGINT = -2
    SIGQUIT = -3
    SIGILL = -4
    SIGTRAP = -5
    SIGABRT = -6
    SIGBUS = -7
    SIGFPE = -8
    SIGKILL = -9
    SIGUSR1 = -10
    SIGSEGV = -11
    SIGUSR2 = -12
    SIGPIPE = -13
    SIGALRM = -14
    SIGTERM = -15
    SIGSTKFLT = -16
    SIGCHLD = -17
    SIGCONT = -18
    SIGSTOP = -19
    SIGTSTP = -20
    SIGTTIN = -21
    SIGTTOU = -22
    SIGURG = -23
    SIGXCPU = -24
    SIGXFSZ = -25
    SIGVTALRM = -26
    SIGPROF = -27
    SIGWINCH = -28
    SIGIO = -29
    SIGPWR = -30
    SIGSYS = -31

class Harness():

    def __init__(self, program: str, seed: str, fuzzer: Fuzz, useGDB:bool=True) -> None:
        self.program = program
        self.seed = seed
        self.fuzzer = fuzzer

        self.QUEUE_SIZE = 1000
        self.MAX_TESTS = 100000000
        self.TESTERS = 30
        self.FUZZERS = 1
        self.LOGFILE = open('log.out', 'w')

        self.queue = Queue(maxsize=self.QUEUE_SIZE)
        self.counter = 0
        self.gdbDetections = 0
        self.c_semaphore = Semaphore()

        self.crashes = 0
        self.crashes_semaphore = Semaphore()

        self.isStarted = False
        self.s_semaphore = Semaphore()

        self.success = False
        self.crash_type = None
        self.success_semaphore = Semaphore()

        self.code_paths = list()
        self.code_paths_semaphore = Semaphore()

        self.out_semaphore = Semaphore()
        self.outfile = open('bad.txt', 'w')

        if isinstance(fuzzer, JSON_Fuzz):
            self.useGDB=False
        else:
            self.useGDB=useGDB


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
                # Note: GdbTesting ignores this. This, therefore, renders the fuzz function as unused.
                fuzzInput = self.queue.get(timeout=0.2)
                pass
            except Empty:
                pass
            else:
                try:
                    if self.useGDB:
                        # GDB Testing
                        gdb = GdbController()
                        payload = Gdb(gdb, self.program, self.queue, t, self.code_paths, self.code_paths_semaphore).start()
                        gdb.exit()
                        if payload:
                            try:
                                self.c_semaphore.acquire()
                                self.gdbDetections += 1
                                self.c_semaphore.release()
                                # Verify the payload with recreation
                                fuzzInput, signal = payload
                                subprocess.run(self.program, input=fuzzInput, check=True, stdout=PIPE, text=True)
                                self.LOGFILE.write(fuzzInput+'\n...\n')
                            except (ValueError):
                                pass
                    else:
                        subprocess.run(self.program, input=fuzzInput, check=True, stdout=PIPE, text=True)
                        self.LOGFILE.write(fuzzInput+'\n...\n')


                except subprocess.CalledProcessError as e:
                    self.out_semaphore.acquire()
                    self.outfile.write(fuzzInput + '\n')
                    self.success_semaphore.acquire()
                    self.success = True
                    self.crash_type = Error(e.returncode).name
                    self.success_semaphore.release() 
        sys.exit(0)

        
    def fuzz(self) -> None:
        """
        Fuzzer function generates mutations and places mutations on to the queue
        """
        t = current_thread()
        t.alive = True
        for _ in range(self.MAX_TESTS):
            if t.alive == True:
                '''
                # Legit input to validate that no segfault occurs initially before fuzzer output used
                for i in range(100000):
                    try:
                        self.queue.put(r'{"len": 12, "input": "AAAABBBBCCCC", "more_data": ["a", "bb"]}')                    
                    except Full:
                        pass
                '''
                try:
                    input = self.fuzzer.fuzz()
                    if input != None:
                        self.queue.put(self.fuzzer.fuzz())
                        self.c_semaphore.acquire()
                        self.counter += 1
                        self.c_semaphore.release()         
                except Full:
                    pass
            else:
                break   
        sys.exit(0)


    def finish(self):
        print('Closing threads...')
        total = len(enumerate()) - 1
        counter = 1
        for t in enumerate():
            if t is not main_thread():
                print(f"Closing thread {counter} of {total}....", end="")
                t.alive = False
                t.join(1)
                print(f"closed")
                counter += 1
        self.LOGFILE.close()
        self.outfile.close()


    def monitor(self, refresh_time=1) -> None:
        self.start()
        # Set defaults
        #curr_count = self.counter
        curr_count = self.counter - self.queue.qsize()
        prev_count = 0
        start_time = time.time()
        curr_time = start_time
        prev_time = 0
        curr_rate = 0
        total_rate = 0
        total_time = str(datetime.timedelta(seconds = round(curr_time - start_time)))
        slow_interval = 0
        paths = 0
        if self.useGDB == 1:
            code_coverage = 0
            paths = 0
            gdbusage = 'Yes'
        else:
            code_coverage = 'N/A'
            paths = 'N/A'
            gdbusage = 'No'
        prev_coverage = 0
        coverage_interval = 0
        threads = len(enumerate()) - self.FUZZERS - 1
        timer = 0
        

        # Start monitoring loop
        try:
            time.sleep(2)
            start = time.time()
            #while time.time() < start + 3*60:
            while True:
                if prev_time != 0 and self.success == False:

                    # Create the table
                    table1 = {
                        "Binary Name":self.program,
                        "Run Time":total_time,
                        "Total Tests":curr_count,
                        "Current tests\sec":curr_rate,
                        "Total tests\sec":total_rate,
                        "Queue Length":self.queue.qsize(),
                    }
                    table2 = {
                        "Total Crashes":self.crashes,
                        "GDB Detect":self.gdbDetections,
                        "Using GDB":gdbusage,
                        "Code Paths":paths,
                        "Code Coverage":code_coverage,
                        "Thread Number":threads,
                    }
                    
                    table_format1 = "{:<20}" * (len(table1.keys()) + 1)
                    table_format2 = "{:<20}" * (len(table2.keys()) + 1)

                    # Print output
                    if sys.platform == 'linux' or sys.platform == 'darwin':
                        os.system("clear")
                    elif sys.platform == 'win32':
                        os.system("cls")

                    # Update variables
                    curr_time = time.time()
                    #curr_count = self.counter
                    curr_count = self.counter - self.queue.qsize()
                    total_time = str(datetime.timedelta(seconds = round(curr_time - start_time)))
                    curr_rate = round((curr_count-prev_count)/(curr_time - prev_time))
                    total_rate = round(curr_count/(curr_time - start_time))
                    threads = len(enumerate()) - self.FUZZERS - 1

                    if self.useGDB == 1:
                        if len(self.code_paths) > 2:
                            paths = len(self.code_paths) - 1
                            code_coverage = round(paths/self.code_paths[0],2)
                        if prev_coverage == code_coverage:
                            coverage_interval += 1
                        elif prev_coverage < code_coverage:
                            coverage_interval = 0
                    if curr_rate == 0 and slow_interval < 10:
                        slow_interval += 1
                    elif curr_rate > 0 and slow_interval > 0:
                        slow_interval -= 1

                    print(table_format1.format("", *table1.keys())) # Prints the headers
                    print(table_format1.format("", *table1.values())) # Prints the values
                    print()
                    print(table_format2.format("", *table2.keys())) # Prints the headers
                    print(table_format2.format("", *table2.values())) # Prints the values
                    print()
                    print("Press Ctrl + C to exit.")
                    if timer > 15:
                        if slow_interval > 5:
                            print("The fuzzer seems to stuck. Consider restarting.")
                        else:
                            print()
                        if coverage_interval > 30 and self.useGDB == 1:
                            print("Code coverage has is no longer increasing. Possible infinite loop.")

                elif self.success == True:
                    print(f"Success! Crash type: {self.crash_type}")
                    self.finish()
                    print('Output saved to bad.txt')  
                    return                    

                prev_time = curr_time
                prev_count = curr_count
                prev_coverage = code_coverage
                timer += 1
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
