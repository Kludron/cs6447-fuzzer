
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
    def __init__(self, gdb: GdbController, binary: str, queue: Queue, thread) -> None:
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

        self.counter = 0    #SB added counter and semaphore to test known bad text
        self.c_semaphore = Semaphore()

        if not os.path.isfile(binary):
            raise FileNotFoundError
        # Load the file into gdb
        self.__write(f'file {binary}')

    def setup(self) -> None:
        # Get all functions
        func_info = self.__getConsole(self.gdb.write('info functions'))
        functions = self.__getFunctions(func_info, specifier=self.__isGoodFunction)
        
        # Get all input functions
        input_funcs = self.__getFunctions(func_info, specifier=self.__isInputFunction)
        
        # Set persistent breakpoints at input functions
        if len(input_funcs) < 1:
            # Binary does not have any input functions
            # raise Exception("Could not detect any input functions")
            print("Could not detect any input functions")
        else:
            self.input_bpoints = self.__makeBreakpoints(input_funcs, self.input_bpoints, bktype='tbreak') #SB Update to tbreak
        #pprint(self.input_bpoints)
        #pprint(f'---------------------------------------------')


        # Set temporary breakpoints at all functions
        if len(functions) < 1:
            raise Exception("Could not detect any functions")
            # print("Could not detect any functions")
        else:
            self.func_bpoints = self.__makeBreakpoints(functions, self.func_bpoints, bktype='tbreak') 
        #pprint(self.func_bpoints)
        #pprint(f'---------------------------------------------')
        
        
        
        
        
    
        # print("Breakpoints: ", len(self.func_bpoints) + len(self.input_bpoints))

        # Create breakpoint at _exit
        response = self.__write('start')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        self.__setResumeOnExit('*&_exit')
        #response = self.__write('b *&_exit')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        response = self.__write('info breakpoints')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        # Continue after start
        response = self.__write('continue')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        # Set the default payload
        payload = ""

    #def start(self) -> None:
    def workinprogress(self) -> None:
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
                continue                 #SB added
            # print(message)
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
                    #print('reason == breakpoint-hit')
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
                            print(f'{self.thread}: signal-recieved')
                            print(f'{self.thread}: {payload}')
                            print(f'{self.thread}: {output["signal-name"]}')
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
                        #pprint(f'{self.thread}:\n{response}')
                        self.__doBacktrace(response)
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
                self.c_semaphore.acquire()      #SB this temporarily to test with known bad text
                self.counter += 1
                self.c_semaphore.release()
                # if self.counter == 20:
                #     response = self.__write(self.BAD)
                # else:
                #     response = self.__write(f'{payload}')
                
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


    def start(self) -> None:
        # Get all functions
        func_info = self.__getConsole(self.gdb.write('info functions'))
        functions = self.__getFunctions(func_info, specifier=self.__isGoodFunction)
        
        # Get all input functions
        input_funcs = self.__getFunctions(func_info, specifier=self.__isInputFunction)
        
        # Set persistent breakpoints at input functions
        if len(input_funcs) < 1:
            # Binary does not have any input functions
            # raise Exception("Could not detect any input functions")
            print("Could not detect any input functions")
        else:
            self.input_bpoints = self.__makeBreakpoints(input_funcs, self.input_bpoints, bktype='tbreak') #SB Update to tbreak
        #pprint(self.input_bpoints)
        #pprint(f'---------------------------------------------')


        # Set temporary breakpoints at all functions
        if len(functions) < 1:
            raise Exception("Could not detect any functions")
            # print("Could not detect any functions")
        else:
            self.func_bpoints = self.__makeBreakpoints(functions, self.func_bpoints, bktype='tbreak') 
        #pprint(self.func_bpoints)
        #pprint(f'---------------------------------------------')
        
        
        
        
        
    
        # print("Breakpoints: ", len(self.func_bpoints) + len(self.input_bpoints))

        # Create breakpoint at _exit
        response = self.__write('start')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        self.__setResumeOnExit('*&_exit')
        #response = self.__write('b *&_exit')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        response = self.__write('info breakpoints')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        # Continue after start
        response = self.__write('continue')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        # Set the default payload
        payload = ""
        #while True:
        while self.thread.alive:    #SB need to enable this again
        # print(self.__getConsole(self.gdb.write('info breakpoints')))
        # return
            
            if response:
                #pprint(f'---------------------------------------------')
                #pprint("response set")
                #pprint(f'---------------------------------------------')
                #pprint(f'{self.thread}:')
                #pprint(f'{response}')
                try:
                    recopy = response  #SB made a copy of response before update below as needed for when we receive response to 'backtrace command'
                    response = response[-1]
                    message = response['message']
                except (TypeError, KeyError, IndexError) as e:
                    # print(response)
                    # print(payload)
                    break
            else:
                #pprint(f'---------------------------------------------')
                #pprint("response NOT set")
                #pprint(f'---------------------------------------------')
                response = self.__write('continue') #SB change this from self.__write('finish')
                #pprint(response)
                #response = self.__write('run')     #SB commented out
                #pprint(response)
                continue                 #SB added
            # print(message)
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
                    #print('reason == breakpoint-hit')
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
                            print(f'{self.thread}: signal-recieved')
                            print(f'{self.thread}: {payload}')
                            print(f'{self.thread}: {output["signal-name"]}')
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
                        #pprint(f'{self.thread}:\n{response}')
                        self.__doBacktrace(response)
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
                self.c_semaphore.acquire()      #SB this temporarily to test with known bad text
                self.counter += 1
                self.c_semaphore.release()
                # if self.counter == 20:
                #     response = self.__write(self.BAD)
                # else:
                #     response = self.__write(f'{payload}')
                
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


    ##############################
    #
    #        Helper functions
    #
    ##############################

    ###################
    #   Parse input
    ###################

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
        # Set up variables
        try:
            btID = str(response[0]["payload"].split()[1])
            bt_list = []
            path = ''
        except (TypeError, KeyError, IndexError):
            return
        
        if len(response) < 2: return

        # This excludes the first and last elements [TODO] Check if this was intended
        # #SB from what I saw, the backtrace messages we need start from the second message and end with the 
        # second last message, range below should be fine
        for i in response[1:-1]:
            try:
                key = i['payload'].split(' in ')
            except (KeyError, TypeError):
                continue

            #Store backtrace path as list in backtrace[btID]
            try:
                bt_list.append({ 
                    "addr" : key[0].split()[1],     
                    "func" : key[1].split()[0]
                })
                path = path + key[0].split()[1]
            except (IndexError, TypeError):
                continue

        # Hash instruction pointer path as key
        path = hashlib.sha256(path.encode('utf-8')).hexdigest()
        if path not in self.backtrace:
            #Add path to backtrace list using hash as key
            self.backtrace[path] = {
                "bt_id" : btID,
                "path"  : bt_list
            }
            # print('Found new path')         

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
