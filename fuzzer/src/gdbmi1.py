import sys
import os
from pygdbmi.gdbcontroller import GdbController
from pygdbmi.constants import GdbTimeoutError
from pwn import cyclic_gen
from pprint import pprint
from queue import Queue
import time
import hashlib

def run_external_command(cmd : str) -> str:
    # os.
    pass

gdb = GdbController(time_to_check_for_additional_output_sec=0.36)

def checkpointRestore(cpID):
    #Restore to base checkpoint thread, update curr checkpoint thread and delete old checkpoint thread
    getConsole(gdb.write(f'restart {cpoints[cpID]["base"]}'))
    getConsole(gdb.write(f'delete checkpoint {cpoints[cpID]["curr"]}'))
    cp = getConsole(gdb.write(f'checkpoint'))
    cp_num = cp.split()[1].strip(":")
    cpoints[cpID]["curr"] = cp_num
    getConsole(gdb.write(f'restart {cpoints[cpID]["curr"]}'))
    print(getConsole(gdb.write(f'info checkpoint')))

def checkpointCreate(cpID):
    #Create initial checkpoint thread and record checkpoint number as current and base
    #New checkpoint thread will remain idle until checkpoint is restored
    cp = getConsole(gdb.write(f'checkpoint'))
    cp_num = cp.split()[1].strip(":")
    cpoints[cpID] = { "base" : cp_num,
                      "curr" : cp_num}

def checkpointUpdate(cpID):
    #Update base for given checkpoint ID, delete old base checkpoint
    getConsole(gdb.write(f'delete checkpoint {cpoints[cpID]["base"]}'))
    cp = getConsole(gdb.write(f'checkpoint'))
    cp_num = cp.split()[1].strip(":")
    cpoints[cpID]["base"] = cp_num

def run(filename) -> str:
    global cpoints
    global func_bpoints
    global input_bpoints
    global backtrace
    global response
    cpoints = {}
    func_bpoints = {}
    input_bpoints = {}
    backtrace = {}
    # Load the file
    gdb.write(f'file {filename}')

    #get all input functions and set permanent breakpoints for each
    inputFunctions = getInputFunctions(getConsole(gdb.write('info functions')))
    if len(inputFunctions) == 0:
        print("binary does not have any input functions")
    else:
        input_bpoints = makeBreakpoints(inputFunctions, input_bpoints)

    #get all functions and set temporary breakpoints for each
    functions = getFunctions(getConsole(gdb.write('info functions')))
    if len(functions) == 0:
        print("binary does not have any functions")
    else:
        func_bpoints = makeTempBreakpoints(functions, func_bpoints)

    #create breakpoint at _exit to rerun if exits cleanly
    gdb.write(f'start')
    setResumeOnExit("*&_exit")
    response = gdb.write('run')

    while True:
        #pprint(response)
        if response[-1]["message"] == 'stopped':
            if response[-1]["payload"]["reason"] == 'breakpoint-hit':           #Occurs when permanent breakpoint hit
                cpID = time.time()
                if response[-1]["payload"]["frame"]["addr"] in input_bpoints:   #Check if breakpoint is an input function
                    checkpointCreate(cpID)
                response = gdb.write(f'backtrace {cpID}', timeout_sec=0.36)                        #Store the path   
            elif response[-1]["payload"]["reason"] == 'exited-normally':        #Program exited
                print('Program did not crash')        
                print('We should not get here')        
                break
        elif response[-1]["message"] == 'breakpoint-deleted':                   #Temp breakpoint hit and deleted
            print(f'Hit function for first time, deleting a temporary breakpoint')
            cpID = time.time()
            response = gdb.write(f'backtrace {cpID}', timeout_sec=0.36)  
        elif response[-1]["message"] == 'done':                                 #Previous execute command completed and returning
            if 'backtrace' in response[0]["payload"]:
                doBacktrace(response)
                response = gdb.write('continue', timeout_sec=0.36)  
        elif response[-1]["message"] == 'running':                              #Binary waiting for input
            print('Supplying input')     
            response = gdb.write('AAAAAAA\n\n', timeout_sec=0.36)    



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

def doBacktrace(response):
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

def setResumeOnExit(breakpoint):
    gdb.write(f'break {breakpoint}')
    gdb.write(f'commands')
    gdb.write(f'run')
    gdb.write(f'end')

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
        #print(point)
        response = gdb.write(f'break *{point[0]}')
        #print(response)
        #pprint(f"makeBreakpoints - response break *{point[1]}:\n{response}\n----------")  
        if response[2]['payload']['bkpt']['type'] == 'breakpoint':
            if 'at' in response[2]['payload']['bkpt']:
                bplist[response[2]['payload']['bkpt']['addr']] = { "number" : response[2]['payload']['bkpt']['number'],
                                                                   "at"     : response[2]['payload']['bkpt']['at']}
            else:
                bplist[response[2]['payload']['bkpt']['addr']] = { "number" : response[2]['payload']['bkpt']['number'],
                                                                   "at"     : response[2]['payload']['bkpt']['number']}            
    return bplist

def makeTempBreakpoints(points, bplist) -> True:
    for point in points:
        response = gdb.write(f'tbreak *{point[0]}')
        if response[2]['payload']['bkpt']['type'] == 'breakpoint':
            bplist[response[2]['payload']['bkpt']['addr']] = { "number" : response[2]['payload']['bkpt']['number'],
                                                               "at"     : response[2]['payload']['bkpt']['at']}
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