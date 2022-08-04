import sys
import os
from pygdbmi.gdbcontroller import GdbController
from pygdbmi.constants import GdbTimeoutError
from pwn import cyclic_gen
from pprint import pprint
from queue import Queue
from time import time
import hashlib

def run_external_command(cmd : str) -> str:
    # os.
    pass

gdb = GdbController(time_to_check_for_additional_output_sec=0.36)

def cpRestore(cpID):
    #Restore to base checkpoint thread, update curr checkpoint thread and delete old checkpoint thread
    getConsole(gdb.write(f'restart {cpoints[cpID]["base"]}'))
    getConsole(gdb.write(f'delete checkpoint {cpoints[cpID]["curr"]}'))
    cp = getConsole(gdb.write(f'checkpoint'))
    cp_num = cp.split()[1].strip(":")
    cpoints[cpID]["curr"] = cp_num
    getConsole(gdb.write(f'restart {cpoints[cpID]["curr"]}'))
    print(getConsole(gdb.write(f'info checkpoint')))

def cpCreate(cpID):
    #Create initial checkpoint thread and record checkpoint number as current and base
    #New checkpoint thread will remain idle until checkpoint is restored
    cp = getConsole(gdb.write(f'checkpoint'))
    cp_num = cp.split()[1].strip(":")
    cpoints[cpID] = { "base" : cp_num,
                      "curr" : cp_num}

def cpUpdate(cpID):
    #Update base for given checkpoint ID, delete old base checkpoint
    getConsole(gdb.write(f'delete checkpoint {cpoints[cpID]["base"]}'))
    cp = getConsole(gdb.write(f'checkpoint'))
    cp_num = cp.split()[1].strip(":")
    cpoints[cpID]["base"] = cp_num

def run(filename) -> str:
    global cpoints
    global func_bpoints
    global input_bpoints
    cpoints = {}
    func_bpoints = {}
    input_bpoints = {}
    # Load the file
    gdb.write(f'file {filename}')

    #get all input functions and set breakpoints
    inputFunctions = getInputFunctions(getConsole(gdb.write('info functions')))
    #print(f"getInputFunctions return:\n{inputFunctions}\n")
    if len(inputFunctions) == 0:
        print("binary does not have any input functions")
    else:
        input_bpoints = makeBreakpoints(inputFunctions, input_bpoints)
    #print(f"getInputFunctions breakpoints:")
    #pprint(input_bpoints)
    #pprint('___________________________________________')

    #get all functions and set breakpoints
    
    functions = getFunctions(getConsole(gdb.write('info functions')))
    #print(f"getFunctions return:\n{functions}\n")
    if len(functions) == 0:
        print("binary does not have any functions")
    else:
        func_bpoints = makeTempBreakpoints(functions, func_bpoints)
    print(f"getFunctions breakpoints:")
    pprint(func_bpoints)
    #pprint('___________________________________________')

    #create breakpoint at _exit to rerun if exits cleanly
    makeBreakpoints(["_exit"], [])
    response = gdb.write(f'commands')
    print(response)
    response = gdb.write(f'run')
    print(response)
    response = gdb.write(f'end')
    print(response)
   
    #code_path = []
    #code_paths = []
    response = gdb.write('run')
    pprint('___________________________________________')
    backtrace = {}
    while True:
        pprint(response)
        if response[-1]["message"] == 'stopped':
            if response[-1]["payload"]["reason"] == 'breakpoint-hit':           #Occurs when permanent breakpoint hit
                cpID = time()
                if response[-1]["payload"]["frame"]["addr"] in input_bpoints:   #If the breakpoint was for an input fuction create a checkpoint
                    print('Breakpoint is input function')
                    cpCreate(cpID)
                response = gdb.write(f'backtrace {cpID}')                       #Store the path   
            elif response[-1]["payload"]["reason"] == 'exited-normally':        #Program exited
                print('Program did not crash')        
                break
        elif response[-1]["message"] == 'breakpoint-deleted':           #Occurs with temp breakpoints
            print('Hit function and deleting a temporary breakpoint')
            cpID = time()
            response = gdb.write(f'backtrace {cpID}') 
        elif response[-1]["message"] == 'done':
            if 'backtrace' in response[0]["payload"]:             #Parse results of backtrace command
                btID = str(response[0]["payload"].split()[1])
                bt_list = []
                path = ''
                for i in response[1:-1]:
                    k = i['payload'].split(' in ')
                    bt_list.append({ "addr" : k[0].split()[1] ,     #Store backtrace path as list in backtrace[btID]
                                     "func" : k[1].split()[0] })
                    path = path + k[0].split()[1]
                path = hashlib.sha256(path.encode('utf-8')).hexdigest()     #hash instruction pointer path as key
                if path not in backtrace:
                    backtrace[path] = { "bt_id" : btID,
                                        "path"  : bt_list }                         #Add path to backtrace list using hash as key
                    print('Found new path')         
                response = gdb.write('continue')
        elif response[-1]["message"] == 'running':
            print('got running message')        
            response = gdb.write('continue')    
        pprint('___________________________________________')



    return "Buffer Size: " + "Not yet defined" # Not including the header 

    # The below is specific to the csv1 binary file (for testing)
    cyclic = cyclic_gen()
    ret_bufsize = 0
    cur_bufsize = 512 # Some large number to start with
    increment = cur_bufsize
    while ret_bufsize != cur_bufsize:
        payload = 'header,must,stay,intact\n' + '\n'.join([','.join(list(cyclic.get(4).decode())) for _ in range(cur_bufsize)]) + '\n' + '\n'

        ret_bufsize = cur_bufsize
        increment = int(increment/2)
        if checkSegfault(payload):
            cur_bufsize -= increment
        else:
            cur_bufsize += increment
    return "Buffer Size: " + str(ret_bufsize) # Not including the header 

def getConsole(output:str) -> str:
    return ''.join([item['payload'] for item in output if item['type'] == 'console'])

def getFunctions(output:str) -> list:
    # Parse function locations
    #   This first takes the output, splits it to only show the lines that start with 0x, 
    #   then only shows the addresses of those lines that dont point to the plt (have @plt in it)
    return [tuple(pointer.split()) for pointer in [line for line in output.split('\n') if line.startswith('0x')] if isGoodFunction(pointer)]


def getInputFunctions(output:str) -> list:
    # Parse function locations
    #   This first takes the output, splits it to only show the lines that start with 0x, 
    #   then only shows the addresses of those lines that dont point to the plt (have @plt in it)
    return [tuple(pointer.split()) for pointer in [line for line in output.split('\n') if line.startswith('0x')] if isInputFunction(pointer)]

def makeBreakpoints(points, bplist) -> True:
    for point in points:
        response = gdb.write(f'break *{point[0]}')
        #pprint(f"makeBreakpoints - response break *{point[1]}:\n{response}\n----------")  
        if response[2]['payload']['bkpt']['type'] == 'breakpoint':
            bplist[response[2]['payload']['bkpt']['addr']] = { "number" : response[2]['payload']['bkpt']['number'],
                                                               "at" : response[2]['payload']['bkpt']['at']}
    return bplist

def makeTempBreakpoints(points, bplist) -> True:
    for point in points:
        response = gdb.write(f'tbreak *{point[0]}')
        #pprint(f"makeBreakpoints - response break *{point[1]}:\n{response}\n----------")  
        if response[2]['payload']['bkpt']['type'] == 'breakpoint':
            bplist[response[2]['payload']['bkpt']['addr']] = { "number" : response[2]['payload']['bkpt']['number'],
                                                               "at" : response[2]['payload']['bkpt']['at']}
    return bplist

def isGoodFunction(line):
    bad_attributes = ['@plt', 'annobin', '__']
    if any(attr in line for attr in bad_attributes):
        return False
    return True

def isInputFunction(line):
    input_attributes = ['fgets', 'gets', 'scanf']
    if any(attr in line for attr in input_attributes):
        return True
    return False

def getFailCode(output:str)->str:
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

def getRegister(reg):       #testing function to return EIP at various points to check progress
    return getConsole(gdb.write(f'info registers {reg}'))

def getRegisters():
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
        print(f"info registers {register}: {getConsole(gdb.write(f'info registers {register}'))}")
        register_info.append(getConsole(gdb.write(f'info registers {register}')))
    #register_info = getConsole(gdb.write('info registers'))
    return register_info

def checkSegfault(payload) -> bool:
    try:
        gdb.write('run')
        gdb.write(payload, timeout_sec=0.01)
    except GdbTimeoutError:
        print("timeout")
        pass
    output = gdb.write('continue', timeout_sec=0.36)
    notifications = [item for item in output if item['type'] == 'notify']
    for notification in notifications:
        try:
            if notification['payload']['signal-name'] == 'SIGSEGV':
                return True
        except KeyError:
            continue
    return False

if __name__ == '__main__':
    print(run('./csv1'))