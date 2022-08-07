
import sys
import os

from pygdbmi.gdbcontroller import GdbController
from pygdbmi.constants import GdbTimeoutError
from queue import Queue
from threading import Semaphore
from pprint import pprint

import time
import hashlib

from utils import Fuzz

# For testing
from utils import CSV_Fuzz

class Gdb():
    def __init__(self, gdb: GdbController, binary: str, queue: Queue, thread, paths: list, paths_semaphore: Semaphore) -> None:
    # def __init__(self, gdb: GdbController, binary: str, fuzzer: Fuzz, thread, semaphore, counter) -> None:
    # def __init__(self, gdb: GdbController, binary: str, fuzzer: Fuzz) -> None:
        self.gdb = gdb
        self.binary = binary
        self.cpoints = dict()
        self.func_bpoints = dict()
        self.input_bpoints = dict()
        self.backtrace = dict()
        self.response = list()
        self.DEFAULT_TIMEOUT = 0.36
        # self.fuzzer = fuzzer
        self.thread = thread
        # self.semaphore = semaphore
        # self.counter = counter
        self.queue = queue
        self.code_paths = paths
        self.code_paths_semaphore = paths_semaphore

        self.counter = 0    #SB added counter and semaphore to test known bad text
        self.c_semaphore = Semaphore()

        if not os.path.isfile(binary):
            raise FileNotFoundError
        # Load the file into gdb
        self.__write(f'file {binary}')



    def start(self) -> None:
        # Get all functions
        func_info = self.__getConsole(self.gdb.write('info functions'))
        functions = self.__getFunctions(func_info, specifier=self.__isGoodFunction)
        
        # Get all input functions
        input_funcs = self.__getFunctions(func_info, specifier=self.__isInputFunction)
        
        # Set persistent breakpoints at input functions
        if len(input_funcs) < 1:
            # Binary does not have any input functions
            print("Could not detect any input functions")
        else:
            self.input_bpoints = self.__makeBreakpoints(input_funcs, self.input_bpoints, bktype='tbreak')


        # Set temporary breakpoints at all functions
        if len(functions) < 1:
            raise Exception("Could not detect any functions")
        else:
            self.func_bpoints = self.__makeBreakpoints(functions, self.func_bpoints, bktype='tbreak') 
            if len(self.code_paths) == 0:
                #If it hasn't been done already store the number of functions in the binary
                #as the first element in the code_paths list
                self.code_paths_semaphore.acquire()
                self.code_paths.append(len(self.func_bpoints))
                self.code_paths_semaphore.release()

        # Create breakpoint at _exit
        response = self.__write('start')
        self.__setResumeOnExit('*&_exit')
        response = self.__write('continue')

        # Set the default payload
        payload = ""
        while self.thread.alive:            
            if response:
                try:
                    recopy = response
                    response = response[-1]
                    message = response['message']
                except (TypeError, KeyError, IndexError) as e:
                    break
            else:
                response = self.__write('continue') 
                continue
            
            # Check if persistent breakpoint is hit, or program has exited
            if message == 'stopped':
                #print(f'{self.thread}: message == stopped')
                #pprint(recopy)
                try:
                    output = response['payload']
                    reason = output['reason']
                except (KeyError) as e:
                    break
                # print(reason)
                # Check if persistent breakpoint is hit
                if reason == 'breakpoint-hit': 
                    print(f'{self.thread}: message == breakpoint-hit')
                    pprint(f'{self.thread}:\n{recopy}')
                    cpID = time.time()

                    # Check if breakpoint was at an input function
                    try:
                        if response["payload"]["frame"]["addr"] in self.input_bpoints:   
                            # Create a checkpoint at this input function
                            self.__checkpointCreate(cpID)
                    except (KeyError, TypeError):
                        pass
                    finally:
                        # Store the path
                        response = self.gdb.write(f'backtrace {cpID}')
                
                # Check if the program exited normally
                elif reason == 'exited-normally':
                    #print(f'{self.thread}: reason == exited-normally')
                    print(f'{self.thread}: Under normal operations we should not get here') 
                    #response = self.__write('info breakpoints')
                    #pprint(f'{self.thread}:\n{response}')
                    break

                ###### [TODO] What about if the program crashes?
                else:
                    #print(f'{self.thread}: message == else')
                    try:
                        #print()
                        reason = output['reason']
                        signal = output['signal-name']
                        if reason == 'signal-received' and signal != "SIGINT":  #SB updato exclude SIGINT other all return
                            #pprint(f'---------------------------------------------')
                            #print(f'{self.thread}: signal-recieved')
                            #print(f'{self.thread}: {payload}')
                            #print(f'{self.thread}: {output["signal-name"]}')
                            #pprint(f'---------------------------------------------')
                            return (payload, output['signal-name'])

                    except (KeyError):
                        print("="*20 + "Unhandled" + "="*20)
                        print(reason)
                        print(output)
                        # print(response)
                        # print(payload)
                    finally:
                        break

            # Check if temporary breakpoint is hit
            elif message == 'breakpoint-deleted':
                #print(f'{self.thread}: message == breakpoint-deleted')
                #pprint(f'{self.thread}:\n{recopy}')
                # print(f'Hit function for first time, deleting a temporary breakpoint')
                cpID = time.time()
                response = self.gdb.write(f'backtrace {cpID}')

            # Check if previous execute command is completed and returning  
            elif message == 'done':
                #print(f'{self.thread}: message == done')
                #pprint(f'{self.thread}:\n{recopy}')
                try:
                    if 'backtrace' in recopy[0]["payload"]:             #SB updated this response was overwritten and this was broken as a resulr\t
                        #print(f'{self.thread}: parsing backtrace results')
                        #pprint(f'{self.thread}:\n{recopy}')
                        self.__doBacktrace(recopy)
                except (TypeError, KeyError):
                    pass
                finally:
                    response = self.__write('continue')

            # Check if the program is waiting for input
            elif message == 'running':
                #print(f'{self.thread}: message == running' )
                #pprint(f'{self.thread}:\n{recopy}')
                # payload = self.fuzzer.fuzz()
                payload = self.queue.get(timeout=0.2)
                #print(f'{self.thread}: payload: {payload}')
                # self.semaphore.acquire()
                # print(self.counter)
                # self.counter += 1
                # self.semaphore.release()
                # print(payload)
                # payload = 'header,must,stay,intact\n'
                # payload += 'a,a,a,a\n' * 120  
                #self.c_semaphore.acquire()      #SB this temporarily to test with known bad text
                #self.counter += 1
                #self.c_semaphore.release()
                # if self.counter == 20:
                #     response = self.__write(self.BAD)
                # else:
                response = self.__write(f'{payload}')
                
                #response = self.__write(f'{payload}')
                #pprint(f'{self.thread}:{response}')
            elif message == 'breakpoint-modified':
                #print(f'{self.thread}: message == breakpoint-modified' )
                #pprint(f'{self.thread}:\n{recopy}')
                response = self.__write('continue')

            else:
            #    print(f'{self.thread}: else -> self.__setResumeOnExit')        #SB Commented these out as I think __setResumeOnExit only need to be run before loop        
            #    self.__setResumeOnExit
                #pprint(f'{self.thread}: else')
                #pprint(f'{self.thread}:\n{recopy}')
                pass  #SB may need to remove this else or otherwise populate with other requirements
        if self.thread.alive:
            return payload, response
        else:
            return None


    def __getConsole(self, output:list) -> str:
        """
        params:
            :output: The output from GdbController().write()
        description:
            This function returns the console output as shown in a gdb instance
        """
        return ''.join([item['payload'] for item in output if item['type'] == 'console'])

    def __getFunctions(self, output:list, specifier) -> list:
        """
        params:
            :output: The output from GdbController().write()
        description:
            This function parses the function locations.
            It first takes the output, splits it to only show the 
            lines that have function locations (start with 0x),
            then it filters out the functions that don't satisfy the function
            specifier.
            
        """
        return [tuple(pointer.split()) for pointer in [line for line in output.split('\n') if line.startswith('0x')] if specifier(pointer)]

    def __isGoodFunction(self, line: str) -> bool:
        """
        params:
            :line: The line of input to check against
        description:
            Checks that the line doesn't contain unwanted attributes
        """
        bad_attributes = ['@plt', 'annobin', '__']
        if any(attr in line for attr in bad_attributes):
            return False
        return True

    def __isInputFunction(self, line: str) -> bool:
        """
        params:
            :line: The line of input to check against
        description:
            Checks if the line contains any input function attributes
        """
        input_attributes = ['fgets', 'gets', 'scanf']
        if any(attr in line for attr in input_attributes):
            return True
        return False

    def __getFailCode(self, output:list) -> list:
        """
        params:
            :output: GdbController().write() output
        description:
            Returns a list of all fail codes found in the output.
        """
        notifications = [item['payload'] for item in output if item['type'] == 'notify']
        fails = list()
        for notification in notifications:
            try:
                signal = notification['signal-name']

                # location = notification['frame']['addr']
            except KeyError:
                fails.append(notification)
            else:
                # fails.append((signal, location))
                fails.append(notification)
        return fails

    def __getRegister(self, reg: str) -> str:
        """
        params:
            :reg: The register to check
        description:
            Testing function to return EIP at various points to check progress
        """
        return self.__getConsole(self.__write(f'info registers {reg}'))

    def __getRegisters(self) -> list:
        # These are the registers we want information from
        registers = [
             'eax',
             'ebx',
             'eip',
             'esp',
             'ecx',
             'edx',
        ]
        register_info = list()
        for register in registers:
            # print(f"info registers {register}: {self.__getConsole(self.__write(f'info registers {register}'))}")
            register_info.append(self.__getConsole(self.__write(f'info registers {register}')))
        #register_info = getConsole(self.__write('info registers'))
        return register_info

    ###################
    #    Gdb Queries
    ###################

    def __write(self, content:str) -> list:
        """
        params:
            :content: The string to send to self.gdb.write()
        description:
            This is just to simplify all self.gdb.write() with the same timeout period
        """
        try:
            return self.gdb.write(content, timeout_sec=self.DEFAULT_TIMEOUT)
        except GdbTimeoutError:
            return []

    def __setResumeOnExit(self, breakpoint) -> None:
        self.__write(f'break {breakpoint}')
        self.__write('commands')
        self.__write('jump _start') #SB updated from self.__write('run')
        self.__write('end')

    def __makeBreakpoints(self, points, bplist:list, bktype='break') -> list:
        """
        params:
            :points: list of breakpoints
            :bplist: output list to add breakpoint information to
            :bktype: defaults to persistent breakpoint. Set to 'tbreak' for temporary
                breakpoint.
        description:
            Sets the breakpoints specified in the points parameter, and updates the bplist
            with these points.
        """
        for point in points:
            response = self.__write(f'{bktype} *{point[0]}')
            try:
                bkpt = response[2]['payload']['bkpt']
                if bkpt['type'] == 'breakpoint':
                    bplist[bkpt['addr']] = { 
                        "number" : bkpt['number'],
                        "at"     : bkpt['at']
                    } 
            except (KeyError, IndexError, TypeError):
                continue
        return bplist

    def __doBacktrace(self, response) -> None:
        if len(response) < 2: return
        path = ''
        for i in response[1:-1]:
            try:
                key = i['payload'].split(' in ')
            except (KeyError, TypeError):
                continue
            try:
                path = path + key[0].split()[1] + ' '
            except (IndexError, TypeError):
                continue

        # Hash instruction pointer path as key
        path = hashlib.sha256(path.encode('utf-8')).hexdigest()
        if path not in self.code_paths:
            self.code_paths_semaphore.acquire()
            self.code_paths.append(path)
            self.code_paths_semaphore.release()

    #############################
    #    Checkpoint Functions
    #############################

    def __checkpointRestore(self, cpID):
        #Restore to base checkpoint thread, update curr checkpoint thread and delete old checkpoint thread
        self.__write(f'restart {cpoints[cpID]["base"]}')
        self.__write(f'delete checkpoint {cpoints[cpID]["curr"]}')
        cp = self.__getConsole(self.gdb.write(f'checkpoint'))
        cp_num = cp.split()[1].strip(":")
        self.cpoints[cpID]["curr"] = cp_num
        self.__write(f'restart {cpoints[cpID]["curr"]}')
        # print(self.__getConsole(self.__write(f'info checkpoint')))

    def __checkpointCreate(self, cpID):
        #Create initial checkpoint thread and record checkpoint number as current and base
        #New checkpoint thread will remain idle until checkpoint is restored
        cp = self.__getConsole(self.__write(f'checkpoint'))
        cp_num = cp.split()[1].strip(":")
        self.cpoints[cpID] = { "base" : cp_num,
                          "curr" : cp_num}

    def __checkpointUpdate(self, cpID):
        #Update base for given checkpoint ID, delete old base checkpoint
        self.__getConsole(self.__write(f'delete checkpoint {cpoints[cpID]["base"]}'))
        cp = self.__getConsole(self.__write(f'checkpoint'))
        cp_num = cp.split()[1].strip(":")
        self.cpoints[cpID]["base"] = cp_num


if __name__ == '__main__':
    gdb = Gdb(GdbController(), sys.argv[1], CSV_Fuzz('header,must,stay,intact\na,b,c,def\ngh,123,aom,test'))
    gdb.start()
