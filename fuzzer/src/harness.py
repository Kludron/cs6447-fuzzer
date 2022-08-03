
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

#BINARY RETURN CODES
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
        self.crash_type = None
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
                    subprocess.run(self.program, input=fuzzInput, check=True, stdout=PIPE, text=True, preexec_fn = lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
                    self.LOGFILE.write(fuzzInput+'\n...\n')
                except subprocess.CalledProcessError as e:
                    self.out_semaphore.acquire()
                    self.outfile.write(fuzzInput + '\n')
                    self.success_semaphore.acquire()
                    self.success = True
                    if e.returncode == SIGHUP:
                        self.crash_type = "SIGHUP"
                    elif e.returncode == SIGINT:
                        self.crash_type = "SIGINT"
                    elif e.returncode == SIGQUIT:
                        self.crash_type = "SIGQUIT"
                    elif e.returncode == SIGILL:
                        self.crash_type = "SIGILL"
                    elif e.returncode == SIGTRAP:
                        self.crash_type = "SIGTRAP"
                    elif e.returncode == SIGABRT:
                        self.crash_type = "SIGABRT"
                    elif e.returncode == SIGBUS:
                        self.crash_type = "SIGBUS"
                    elif e.returncode == SIGFPE:
                        self.crash_type = "SIGFPE"
                    elif e.returncode == SIGKILL:
                        self.crash_type = "SIGKILL"
                    elif e.returncode == SIGUSR1:
                        self.crash_type = "SIGUSR1"
                    elif e.returncode == SIGSEGV:
                        self.crash_type = "SIGSEGV"
                    elif e.returncode == SIGUSR2:
                        self.crash_type = "SIGUSR2"
                    elif e.returncode == SIGPIPE:
                        self.crash_type = "SIGPIPE"
                    elif e.returncode == SIGALRM:
                        self.crash_type = "SIGALRM"
                    elif e.returncode == SIGTERM:
                        self.crash_type = "SIGTERM"
                    elif e.returncode == SIGSTKFLT:
                        self.crash_type = "SIGSTKFLT"
                    elif e.returncode == SIGCHLD:
                        self.crash_type = "SIGCHLD"
                    elif e.returncode == SIGCONT:
                        self.crash_type = "SIGCONT"
                    elif e.returncode == SIGSTOP:
                        self.crash_type = "SIGSTOP"
                    elif e.returncode == SIGTSTP:
                        self.crash_type = "SIGTSTP"
                    elif e.returncode == SIGTTIN:
                        self.crash_type = "SIGTTIN"
                    elif e.returncode == SIGTTOU:
                        self.crash_type = "SIGTTOU"
                    elif e.returncode == SIGURG:
                        self.crash_type = "SIGURG"
                    elif e.returncode == SIGXCPU:
                        self.crash_type = "SIGXCPU"
                    elif e.returncode == SIGXFSZ:
                        self.crash_type = "SIGXFSZ"
                    elif e.returncode == SIGVTALRM:
                        self.crash_type = "SIGVTALRM"
                    elif e.returncode == SIGPROF:
                        self.crash_type = "SIGPROF"
                    elif e.returncode == SIGWINCH:
                        self.crash_type = "SIGWINCH"
                    elif e.returncode == SIGIO:
                        self.crash_type = "SIGIO"
                    elif e.returncode == SIGPWR:
                        self.crash_type = "SIGPWR"
                    elif e.returncode == SIGSYS:
                        self.crash_type = "SIGSYS"
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
                    print(f"Success! Crash type: {self.crash_type}")
                    self.finish()
                    print('Output saved to bad.txt')  
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