from asyncio import subprocess
from itertools import count
from subprocess import PIPE
import sys
import os

# if (os.path.exists("testBad.txt")):
#     os.remove("testBad.txt")
# try:
#     out =  open("testBad.txt", "w")
# except:
#     exit
    
out = open("testBad.txt", "w")

binary, seed = sys.argv[1], sys.argv[2]

try:
    with open(seed) as file:
        lines = file.readlines()
        lines = [line.rstrip() for line in lines]
        print(len(lines))
        
    for line in lines:
        try:
            # out.write("Testing " + line + "\n")
            print("Testing " + line + "\n")
            subprocess.run(binary, input=line, stdout=PIPE, stderr=PIPE, text=True, check=True)
        except subprocess.CalledProcessError as e:
            out.write(line + '\n')
            continue
        else:
            print("???")
            pass
            
except:
    pass