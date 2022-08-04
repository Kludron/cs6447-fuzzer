import sys
import os
from pygdbmi.gdbcontroller import GdbController
from pygdbmi.constants import GdbTimeoutError
from pwn import cyclic_gen
from pprint import pprint
from queue import Queue
from time import time

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
    print(f"getInputFunctions return:\n{inputFunctions}\n")
    if len(inputFunctions) == 0:
        print("binary does not have any input functions")
    else:
        input_bpoints = makeBreakpoints(inputFunctions, input_bpoints)
    print(f"getInputFunctions breakpoints:")
    pprint(input_bpoints)
    pprint('___________________________________________')

    #get all functions and set breakpoints
    
    functions = getFunctions(getConsole(gdb.write('info functions')))
    print(f"getFunctions return:\n{functions}\n")
    if len(functions) == 0:
        print("binary does not have any functions")
    else:
        func_bpoints = makeBreakpoints(functions, func_bpoints)
    print(f"getFunctions breakpoints:")
    pprint(func_bpoints)
    pprint('___________________________________________')

   
    code_path = []
    code_paths = []
    response = gdb.write('run')
    pprint('___________________________________________')
    #pprint(response[-1])
    while True:
        if response[-1]["message"] == 'stopped':
            if response[-1]["payload"]["reason"] == 'breakpoint-hit':
                print(f'Hit breakpoint: {response[-1]["payload"]["frame"]["addr"]}')
                if response[-1]["payload"]["frame"]["addr"] in input_bpoints:   #Check if breakpoint is an input
                    print('Breakpoint is input function')
                    cpID = time()
                    cpCreate(cpID)
                    response = gdb.write('backtrace')
                else:       #breakpoint is some function breakppint, add it to the code path
                    code_path.append(response[-1]["payload"]["frame"]["addr"])
                    response = gdb.write('backtrace')
        elif response[-1]["message"] == 'done':             #some command has returned output
            if response[0]["payload"] == 'backtrace\n':
                backtrace = []
                for i in response[1:-1]:
                    print(i['payload'])
                    i['payload'].split(' in ')
                    backtrace.append( {  })
                response = gdb.write('continue')
        elif response[-1]["message"] == 'running':
            pass
        pprint('___________________________________________')

    


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
    print("Buffer Size: " + str(ret_bufsize)) # Not including the header
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