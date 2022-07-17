# Utilities for COMP6447 Fuzzer
import sys
import json
import xml.etree.ElementTree as ElementTree
from pwn import *

from fuzzer.src.csv_fuzzer import run_csv_fuzzer

TYPE_FAIL = -1
TYPE_CSV = 0
TYPE_JSON = 1
TYPE_JPG = 2
TYPE_XML = 3
TYPE_PLAINTEXT = 4

# Generic Fuzzer Class
class Fuzz():
    def __init__(self, seed):
        self.seed = seed
    def checkType(self):
        return False
    def mutate():
        pass
    def fuzz(self):
        # The below is just a placeholder for testing purposes
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(8))

# CSV Fuzzer
class CSV_Fuzz(Fuzz):
    def __init__(self, seed):
        super().__init__(seed)
        self.fuzzList = list()

    def checkType(self):
        self.lines = self.seed.split("\n")
        first_row_commas = self.lines[0].count(",")
        
        for line in self.lines:
            if line.count(",") != first_row_commas or first_row_commas == 0:
                return False
        return True

    """
    Mutate the field data, if the line is not empty, with string of characters.
    """
    def __mutate_strings(self, line): # [TODO]
        # If line is empty, return empty line back.
        if not line:
            return line
        # Else, add string of chars at the end to the line.
        # Random letter between A to Z.
        random_letter = random.choice(string.ascii_uppercase)
        i = random.randint(0, 100)
        # Add the random letter 'i' times at the end of the line, separated by commas.
        return line + (i * (random_letter + ","))

    """
    Mutate the field data, if the line is not empty, with integer.
    """
    def __mutate_ints(self, line): #[TODO]
        # If line is empty, return empty line back.
        if not line:
            return line
        # Else, mutate field's data with ints.
        else:
            line_len = len(line.split(",")) - 1
            # i'th field is to be changed with value j.
            i = random.randint(0, line_len)
            j = random.randint(0, 999)
            line[i] = j
            # Change back the line and return.
            line = str(line)
            return ",".join(line) + "\n"

    """
    Mutate the number of lines or the size of the line.
    """
    def __mutate_line(self, line) -> str: #[TODO]
        # Random number between 0 and 100.
        i = random.randint(0, 100)
        
        # 20% chance: delete the line.
        if i < 20:
            return ''
        # 20% chance: do nothing.
        elif i < 40:
            return line
        # 20% chance: add a new line to the current line with all empty fields.
        elif i < 60:
            line_len = len(line.split(",")) - 1
            line = line + "\n" + ("," * line_len)
        # 20% chance: duplicate the line 'i' times.
        elif i < 80:
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
    Run mutations on the input and return the new mutated input as a string.
    """
    def __mutate_input(self, input): #[TODO]
        new_mutated_input = []

        # Run mutations per every line.
        for line in input:
            i = random.randint(0, 100)
            # 50% chance that number or size of the line is mutated.
            if i < 50:
                new_mutated_input.append(self.__mutate_line(line))
            # 25% chance that fields are mutated with ints.
            elif i > 50 and i <= 75:
                new_mutated_input.append(self.__mutate_ints(line))
            # 25% chance that fields are mutated with strings or chars.
            else:
                new_mutated_input.append(self.__mutate_strings(line))
            
            return ''.join(new_mutated_input)

    """
    Function to run the csv fuzzer.
    'binary' is the input csv binary.
    'input_file' is csv1.txt
    """
    def mutate(self) -> list:
        # Open the input file csv1.txt
        with open(self.seed, 'rt', newline='') as file_ptr:
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
                new_mutated_input = self.__mutate_input(new_mutated_input.split("\n"))
                
                # Send the mutations.
                # TODO: Send the input to the binary.
                self.fuzzList.append(new_mutated_input)
                i += 1

    def fuzz(self):
        try:
            return self.fuzzList.pop(0)
        return run_csv_fuzzer(self.seed)

# JSON Fuzzer
class JSON_Fuzz(Fuzz):
    def __init__(self, seed):
        super().__init__(seed)
    def checkType(self):
        try:
            json.loads(self.seed)
            return True
        except ValueError:
            return False
    def mutate():
        pass
    def fuzz(self):
        # Placeholder
        return super().fuzz()

# XML Fuzzer
class XML_Fuzz(Fuzz):
    def __init__(self, seed):  
        super().__init__(seed)
    def checkType(self):
        try:
            ElementTree.fromstring(self.seed)
            return True
        except ElementTree.ParseError:
            return False
    def mutate():
        pass
    def fuzz(self):
        # Placeholder
        return super().fuzz()

# Plaintext Fuzzer. No need to overwrite checkType()
class Plaintext_Fuzz(Fuzz):
    def __init__(self, seed):  
        super().__init__(seed)
    def mutate():
        pass
    def fuzz(self):
        # Placeholder
        return super().fuzz()

# JPG Fuzzer. No need to overwrite checkType()
class JPG_Fuzz(Fuzz):
    def __init__(self, seed):  
        super().__init__(seed)
    # I'm guessing we need to use bit flipping for this one
    def mutate():
        pass
    def fuzz(self):
        # Placeholder
        return super().fuzz()
        

def checkType(filename):
    try:
        fp = open(filename, 'r')
        inputTxt = fp.read().strip()
        if (CSV_Fuzz(inputTxt).checkType()):
            return TYPE_CSV
        elif (JSON_Fuzz(inputTxt).checkType()):
            return TYPE_JSON
        elif (XML_Fuzz(inputTxt).checkType()):
            return TYPE_XML
        else:
            return TYPE_PLAINTEXT
    except IOError:
        return TYPE_FAIL
    except:
        return TYPE_JPG

def getType(filename) -> Fuzz or str:
    try:
        fp = open(filename, 'r')
        inputTxt = fp.read().strip()
        if (CSV_Fuzz(inputTxt).checkType()):
            return CSV_Fuzz(inputTxt)
        elif (JSON_Fuzz(inputTxt).checkType()):
            return JSON_Fuzz(inputTxt)
        elif (XML_Fuzz(inputTxt).checkType()):
            return XML_Fuzz(inputTxt)
        else:
            return Plaintext_Fuzz(inputTxt)
    except IOError:
        return TYPE_FAIL
    except:
        return JPG_Fuzz(inputTxt)

if __name__ == '__main__':
    print("Sample input: ", sys.argv[1])
    
    type = checkType(sys.argv[1])
            
    if type == TYPE_FAIL:
        print("Failed to open file/detect input type")
    elif type == TYPE_CSV:
        print("Detected CSV")
        CSV_Fuzz.fuzz()
    elif type == TYPE_JSON:
        print("Detected JSON")
        JSON_Fuzz.fuzz()
    elif type == TYPE_XML:
        print("Detected XML")
        XML_Fuzz.fuzz()
    elif type == TYPE_PLAINTEXT:
        print("Detected Plaintext")
        Plaintext_Fuzz.fuzz()
    elif type == TYPE_JPG:
        print("Detected JPG")
        JPG_Fuzz.fuzz()
