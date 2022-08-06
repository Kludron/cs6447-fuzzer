
import sys
import os

from pygdbmi.gdbcontroller import GdbController
from pygdbmi.constants import GdbTimeoutError
from queue import Queue

from pprint import pprint

import time
import hashlib

from utils import Fuzz

# For testing
from utils import CSV_Fuzz

class Gdb():
    # def __init__(self, gdb: GdbController, binary: str, fuzzer: Fuzz, thread) -> None:
    def __init__(self, gdb: GdbController, binary: str, fuzzer: Fuzz) -> None:
        self.gdb = gdb
        self.binary = binary
        self.cpoints = dict()
        self.func_bpoints = dict()
        self.input_bpoints = dict()
        self.backtrace = dict()
        self.response = list()
        self.DEFAULT_TIMEOUT = 0.36
        self.fuzzer = fuzzer
        # self.thread = thread

        if not os.path.isfile(binary):
            raise FileNotFoundError
        # Load the file into gdb
        self.__write(f'file {binary}')

    def start(self) -> None:
        # Get all functions
        func_info = self.__getConsole(self.__write('info functions'))
        functions = self.__getFunctions(func_info, specifier=self.__isGoodFunction)
        
        # Get all input functions
        input_funcs = self.__getFunctions(func_info, specifier=self.__isInputFunction)
        
        # Set persistent breakpoints at input functions
        if len(input_funcs) < 1:
            # Binary does not have any input functions
            raise Exception("Could not detect any input functions")
        else:
            self.input_bpoints = self.__makeBreakpoints(input_funcs, self.input_bpoints)
        
        # Set temporary breakpoints at all functions
        if len(functions) < 1:
            raise Exception("Could not detect any functions")
        else:
            self.func_bpoints = self.__makeBreakpoints(functions, self.func_bpoints, bktype='tbreak')

        # print("Breakpoints: ", len(self.func_bpoints) + len(self.input_bpoints))

        # Create breakpoint at _exit
        self.__write('start')
        self.__setResumeOnExit('*&_exit')
        # Run binary
        response = self.__write('run')
        # Set the default payload
        payload = ""
        # while self.thread.alive:
        while True:
            try:
                response = response[-1]
                message = response['message']
            except (TypeError, KeyError) as e:
                # print(response)
                break

            print(message)
            # Check if persistent breakpoint is hit, or program has exited
            if message == 'stopped':
                try:
                    output = response['payload']
                    reason = output['reason']
                except (KeyError) as e:
                    break
                print(reason)
                # Check if persistent breakpoint is hit
                if reason == 'breakpoint-hit': 
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
                        response = self.__write(f'backtrace {cpID}')
                
                # Check if the program exited normally
                elif reason == 'exited-normally':
                    # print('Program did not crash')        
                    # print('We should not get here')        
                    break

                ###### [TODO] What about if the program crashes?
                else:
                    print("="*20 + "Unhandled" + "="*20)
                    print(reason)
                    print(output)
                    print(response)
                    print(payload)
                    break

            # Check if temporary breakpoint is hit
            elif message == 'breakpoint-deleted':
                # print(f'Hit function for first time, deleting a temporary breakpoint')
                cpID = time.time()
                response = self.__write(f'backtrace {cpID}')

            # Check if previous execute command is completed and returning  
            elif message == 'done':
                try:
                    if 'backtrace' in response[0]["payload"]:
                        self.__doBacktrace(response)
                except (TypeError, KeyError):
                    pass
                finally:
                    response = self.__write('continue')

            # Check if the program is waiting for input
            elif message == 'running':
                # print('Supplying input')
                payload = self.fuzzer.fuzz()
                # payload = 'header,must,stay,intact\n'
                # payload += 'a,a,a,a\n' * 120
                response = self.__write(payload)

            else:
                print("="*20 + "Unhandled" + "="*20)
                print(message)
                print(response)
                print(payload)
                break

        return payload


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
            :content: The string to send to self.__write()
        description:
            This is just to simplify all self.__write() with the same timeout period
        """
        try:
            return self.gdb.write(content, timeout_sec=self.DEFAULT_TIMEOUT)
        except GdbTimeoutError:
            return []

    def __setResumeOnExit(self, breakpoint) -> None:
        self.__write(f'break {breakpoint}')
        self.__write('commands')
        self.__write('run')
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
        self.__getConsole(self.__write(f'restart {cpoints[cpID]["base"]}'))
        self.__getConsole(self.__write(f'delete checkpoint {cpoints[cpID]["curr"]}'))
        cp = self.__getConsole(self.__write(f'checkpoint'))
        cp_num = cp.split()[1].strip(":")
        self.cpoints[cpID]["curr"] = cp_num
        self.__getConsole(self.__write(f'restart {cpoints[cpID]["curr"]}'))
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