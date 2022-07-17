import random
from pwn import *

"""
Function to run the csv fuzzer.
'binary' is the input csv binary.
'input_file' is csv1.txt
"""
def run_csv_fuzzer(binary, input_file) -> list:
    # Open the input file csv1.txt
    with open(input_file, 'rt', newline='') as file_ptr:
        # Iteration counter.
        i = 0
        # New mutated input that reads from input_file.
        # This is the input that will be mutated and sent to the binary.
        new_mutated_input = file_ptr.read()

        while i < 999:
            # After every 10 iterations reset the file pointer and the input.
            if i % 10 == 0:
                # Set file ptr to the start.
                file_ptr.seek(0)
                new_mutated_input = file_ptr.read()
            
            # Do the mutations.
            new_mutated_input = mutate_input(new_mutated_input.split("\n"))
            
            # Send the mutations.
            # TODO: Send the input to the binary.
            
            i += 1

"""
Run mutations on the input and return the new mutated input as a string.
"""
def mutate_input(input):
    new_mutated_input = []

    # Run mutations per every line.
    for line in input:
        i = random.randint(0, 100)
        # 50% chance that number or size of the line is mutated.
        if i < 50:
            new_mutated_input.append(mutate_line(line))
        # 25% chance that fields are mutated with ints.
        elif i > 50 and i <= 75:
            new_mutated_input.append(mutate_ints(line))
        # 25% chance that fields are mutated with strings or chars.
        else:
            new_mutated_input.append(mutate_strings(line))
        
        return ''.join(new_mutated_input)

"""
Mutate the number of lines or the size of the line.
"""
def mutate_line(line):
    # Random number between 0 and 100.
    i = random.randint(0, 100)
    
    # 20% chance: delete the line.
    if i < 20:
        return ''
    # 20% chance: do nothing.
    elif i >= 20 and i < 40:
        return line
    # 20% chance: add a new line to the current line with all empty fields.
    elif i >= 40 and i < 60:
        line_len = len(line.split(",")) - 1
        line = line + "\n" + ("," * line_len)
    # 20% chance: duplicate the line 'i' times.
    elif i >= 60 and i < 80:
        # If line is empty, return empty line.
        if line.rstrip() == '':
            return line
        # Else, duplicate the line.
        else:
            return (i * (line + "\n"))
    # 20% chance: increase line length by 'i' times.
    # i here is between 80 and 100.
    else:
        new_line = []
        line = line.split(",")
        for l in line:
            l = i * l.rstrip()
            new_line.append(l)
        return ",".join(new_line)

"""
Mutate the field data, if the line is not empty, with integer.
"""
def mutate_ints(line):
    # If line is empty, return empty line back.
    if line == '':
        return line
    # Else, mutate field's data with ints.
    else:
        line_len = len(line.rstrip().split(",")) - 1
        # i'th field is to be changed with value j.
        i = random.randint(0, line_len)
        j = random.randint(0, 999)
        line[i] = j
        # Change back the line and return.
        line = str(line)
        return ",".join(line) + "\n"
        


"""
Mutate the field data, if the line is not empty, with string of characters.
"""
def mutate_strings(line):
    # If line is empty, return empty line back.
    if line == '':
        return line
    # Else, add string of chars at the end to the line.
    else:
        line_len = len(line.rstrip().split(",")) - 1
        # Random letter between A to Z.
        random_letter = chr(random.randint(ord('A'), ord('Z')))
        i = random.randint(0, 100)
        # Add the random letter 'i' times at the end of the line, separated by commas.
        return line + (i * (random_letter + ","))
