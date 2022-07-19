# Utilities for COMP6447 Fuzzer
import sys
import json
import xml.etree.ElementTree as ElementTree
from pwn import *
import copy
from random import choice
# from tmp_csvFuzz import CSV_Fuzz

# from csv_fuzzer import run_csv_fuzzer

TYPE_FAIL = -1
TYPE_CSV = 0
TYPE_JSON = 1
TYPE_JPG = 2
TYPE_XML = 3
TYPE_PLAINTEXT = 4

# Generic Fuzzer Class
class Fuzz():
    def __init__(self, seed: str):
        self.seed = seed
    def checkType(self):
        return False
    def mutate():
        pass
    def fuzz(self):
        # The below is just a placeholder for testing purposes
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(8))

class CSV_Fuzz(Fuzz):
    
    def __init__(self, seed: str) -> None:
        super().__init__(seed)
        self.mutations = list()
        self.DELIMITER = ','
        self.maxsize = 10000 # Just some obscure value that is large enough to likely cause a segfault. Much larger and the program is killed because it takes up too much memory.
        self.structure = seed.split('\n')[0]
        self.sItems = len(self.structure.split(self.DELIMITER))
        self.__generate()

    def __generate_random(self):
        # Generate strings with random characters
        printable = list(string.printable)
        printable.remove('\n')
        chars = [printable for _ in range(self.sItems)]
        while chars[0]:
            randString = []
            for i in range(1, self.sItems):
                randString.append(chars[i].pop(random.randint(0, len(chars[i])-1)))
            yield self.DELIMITER.join(randString)

    def __generate_long(self):
        for i in range(self.maxsize):
            randString = []
            for _ in range(self.sItems):
                randString.append(random.choice(string.ascii_letters)*random.randint(0,i))
            yield self.DELIMITER.join(randString)

    def __generate_lots(self):
        for _ in range(self.maxsize):
            yield self.DELIMITER.join(list(random.choice(string.ascii_letters)*random.randint(self.sItems,self.maxsize)))

    def __generate_lines(self):
        for i in range(self.maxsize):
            # Create a line with self.sItems items, joined by i \n's
            randLine = []
            for _ in range(self.sItems):
                randLine.append(random.choice(string.ascii_letters))
            randString = self.DELIMITER.join(randLine)
            yield '\n'.join([randString for _ in range(i)])

    def __generate(self):
        for i in self.__generate_long():
            self.mutations.append(i)
        for i in self.__generate_random():
            self.mutations.append(i)
        for i in self.__generate_lots():
            self.mutations.append(i)
        for i in self.__generate_lines():
            self.mutations.append(i)

    def checkType(self):
        self.lines = self.seed.split("\n")
        first_row_commas = self.lines[0].count(",")
        
        for line in self.lines:
            if line.count(",") != first_row_commas or first_row_commas == 0:
                return False
        return True

    def mutate(self):
        self.__generate()

    def fuzz(self):
        try:
            return self.structure + '\n' + self.mutations.pop(0)
        except IndexError:
            self.__generate()
            return self.fuzz()

# # CSV Fuzzer
# class CSV_Fuzz(Fuzz):
#     def __init__(self, seed):
#         super().__init__(seed)
#         self.fuzzList = list()

#     def checkType(self):
#         self.lines = self.seed.split("\n")
#         first_row_commas = self.lines[0].count(",")
        
#         for line in self.lines:
#             if line.count(",") != first_row_commas or first_row_commas == 0:
#                 return False
#         return True

#     """
#     Mutate the field data, if the line is not empty, with string of characters.
#     """
#     def __mutate_strings(self, line): # [TODO]
#         # If line is empty, return empty line back.
#         if not line:
#             return line
#         # Else, add string of chars at the end to the line.
#         # Random letter between A to Z.
#         random_letter = random.choice(string.ascii_uppercase)
#         i = random.randint(0, 100)
#         # Add the random letter 'i' times at the end of the line, separated by commas.
#         return line + (i * (random_letter + ","))

#     """
#     Mutate the field data, if the line is not empty, with integer.
#     """
#     def __mutate_ints(self, line): #[TODO]
#         # If line is empty, return empty line back.
#         if not line:
#             return line
#         # Else, mutate field's data with ints.
#         else:
#             newRow = []
#             for element in line.split(','):
#                 rand_i = random.randint(0, len(element)-1)
#                 newstring = element[:rand_i] + random.choice(string.digits) + element[rand_i+1:]
#                 newRow.append(newstring)
#             # line_len = len(line.split(",")) - 1
#             # # i'th field is to be changed with value j.
#             # i = random.randint(0, line_len)
#             # j = random.randint(0, 999)
#             # # Strings are immutable in python3 [TODO]
#             # newstring = line[:i] + str(j) + line[i+1:]
#             # # line[i] = j
#             # # Change back the line and return.
#             # line = str(line)
#             return ",".join(newRow) + "\n"

#             # a,b,5,d

#     """
#     Mutate the number of lines or the size of the line.
#     """
#     def __mutate_line(self, line) -> str: #[TODO]
#         # Random number between 0 and 100.
#         i = random.randint(0, 100)
        
#         # 20% chance: delete the line.
#         if i < 20:
#             return ''
#         # 20% chance: do nothing.
#         elif i < 40:
#             return line
#         # 20% chance: add a new line to the current line with all empty fields.
#         elif i < 60:
#             line_len = len(line.split(",")) - 1
#             line = line + "\n" + ("," * line_len)
#         # 20% chance: duplicate the line 'i' times.
#         elif i < 80:
#             # If line is empty, return empty line.
#             if line.rstrip() == '':
#                 return line
#             # Else, duplicate the line.
#             else:
#                 return (i * (line + "\n"))
#         # 20% chance: increase line length by 'i' times.
#         # i here is between 80 and 100.
#         else:
#             new_line = []
#             line = line.split(",")
#             for l in line:
#                 l = i * l.rstrip()
#                 new_line.append(l)
#             return ",".join(new_line)

#     """
#     Run mutations on the input and return the new mutated input as a string.
#     """
#     def __mutate_input(self, input:list): #[TODO]
#         new_mutated_input = []

#         # Run mutations per every line.
#         for line in input:
#             i = random.randint(0, 100)
#             # 50% chance that number or size of the line is mutated.
#             if i < 50:
#                 new_mutated_input.append(self.__mutate_line(line))
#             # 25% chance that fields are mutated with ints.
#             elif i > 50 and i <= 75:
#                 new_mutated_input.append(self.__mutate_ints(line))
#             # 25% chance that fields are mutated with strings or chars.
#             else:
#                 new_mutated_input.append(self.__mutate_strings(line))
            
#             try:
#                 return ''.join(new_mutated_input)
#             except TypeError:
#                 return ''

#     """
#     Function to run the csv fuzzer.
#     """
#     def mutate(self) -> list:

#         for _ in range(999):
#             mutated_input = self.__mutate_input(self.seed.split('\n')[1:])
#             mutated_input = self.seed.split('\n')[0] + '\n' + mutated_input
#             self.fuzzList.append(mutated_input)
#         return self.fuzzList

#     def fuzz(self):
#         try:
#             return self.fuzzList.pop(0)
#         except IndexError:
#             # Regenerate a fuzzer input list
#             self.mutate()
#             return self.fuzz() # This could infinite loop [TODO]

# JSON Fuzzer
class JSON_Fuzz(Fuzz):
    def __init__(self, seed):
        super().__init__(seed)
        self.basic_checks = {
            'buffer_overflow': 'A'*999,
            'format': '%p',
            'pos': 1,
            'neg': -1,
            'zero': 0,
            'big_neg': -1111111111111111111111111111111111111111111,
            'big_pos': 1111111111111111111111111111111111111111111
        }
        try:
            self.jsonObj : dict = json.loads(self.seed)
        except Exception:
            self.jsonObj = {}
            
    def checkType(self):
        try:
            json.loads(self.seed)
            return True
        except ValueError:
            return False

    '''
        Perform mutations on input.
        First goes through the basic checks to get basic errors
        Then performs random mutations
    '''
    def mutate(self):
        mutation = ''
        if (self.basic_checks):
            # test for any basic errors
            mutation = self.basicMutate()
        else:
            # otherwise perform random mutation
            mutation = self.dumbMutate()
        return mutation
        
    '''
        As the name implies, performs dumb, random mutations. 
    '''
    def dumbMutate(self):
        mutation = copy.deepcopy(self.jsonObj)
        for key in self.jsonObj:
            if isinstance(self.jsonObj[key], int):
                mutation[key] = randint(-2147483647, 2147483647) # we've already checked for int overflows/underflows in basicMutate()
            elif isinstance(self.jsonObj[key], str):
                mutation[key] = self.mutateString(self.jsonObj[key])
            elif isinstance(self.jsonObj[key], list):
                for index, element in enumerate(self.jsonObj[key]):
                    if isinstance(element, int):
                        mutation[key][index] = randint(-2147483647, 2147483647)
                    elif isinstance(element, str):
                        mutation[key][index] = self.mutateString(element)
        return mutation

    '''
        Fill the mutation with a basic check value and then remove that check
        to quickly identify simple vulnerabilities
    '''
    def basicMutate(self):
        mutation = copy.deepcopy(self.jsonObj)
        first_pair = next(iter((self.basic_checks.items())))
        for key in self.jsonObj:
            mutation[key] = first_pair[1]
        self.basic_checks.pop(first_pair[0])
        return mutation
    
    def mutateString(self, s):
        methods = [
            self.deleteRandomChar,
            self.insertRandomChar,
            self.flipRandomBit,
            self.multipleStringMutations
        ]
        method = choice(methods)
        return method(s)
    
    def deleteRandomChar(self, s):
        if s == '':
            return s
        idx = randint(0, len(s) - 1)
        return s[:idx] + s[idx + 1:]

    def insertRandomChar(self, s):
        idx = randint(0, len(s))
        return s[:idx] + chr(randint(30, 127)) + s[idx:]    # insert random ascii character (excluding )
    
    def flipRandomBit(self, s):
        if s == '':
            return s
        idx = randint(0, len(s) - 1)
        c = s[idx]
        mask = 1 << randint(0,6)    # select random bit position to flip
        flipped = chr(ord(c) ^ mask)    # xor the random character and bitmask
        return s[:idx] + flipped + s[idx + 1:]

    def multipleStringMutations(self, s):
        methods = [
            self.deleteRandomChar,
            self.insertRandomChar,
            self.flipRandomBit
        ]
        mutation = s
        iterations = randint(0, 20)
        for i in range(iterations):
            method = choice(methods)
            mutation = method(mutation)
        return mutation
    
    def fuzz(self):
        return json.dumps(self.mutate())

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
        with open(filename, 'r') as fp:
            inputTxt = fp.read().strip()
            
            if (JSON_Fuzz(inputTxt).checkType()):
                return TYPE_JSON, inputTxt
            elif (XML_Fuzz(inputTxt).checkType()):
                return TYPE_XML, inputTxt
            elif (CSV_Fuzz(inputTxt).checkType()):
                return TYPE_CSV, inputTxt
            else:
                return TYPE_PLAINTEXT, inputTxt
    except IOError:
        return TYPE_FAIL, ''
    except:
        return TYPE_JPG, inputTxt

def getType(filename) -> Fuzz or str:
    try:
        with open(filename, 'r') as fp:
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

