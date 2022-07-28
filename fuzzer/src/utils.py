# Utilities for COMP6447 Fuzzer
import random
import string
import sys
import json
from tkinter import E
import xml.etree.ElementTree as ElementTree
# from pwn import *
import copy
from random import choice, randint

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
    
    
    '''
        Random Int/String generators
    '''
    def generateInt(self):
        return randint(-2147483647, 2147483647)
    def generateOverflowedInt(self):
        if (randint(0,1) == 0):
            return randint(-21474836470000000, -2147483648)
        else:
            return randint(2147483647, 21474836470000000)
    def generateString(self):
        return ''.join(random.choices(string.printable, k=randint(1, 20)))
    
    
    '''
        Random String mutators
    '''
    def flipRandomBit(self, s):
        if s == '':
            return s
        idx = randint(0, len(s) - 1)
        c = s[idx]
        mask = 1 << randint(0,6)    # select random bit position to flip
        flipped = chr(ord(c) ^ mask)    # xor the random character and bitmask
        return s[:idx] + flipped + s[idx + 1:]
    def deleteRandomChar(self, s):
        if s == '':
            return s
        idx = randint(0, len(s) - 1)
        return s[:idx] + s[idx + 1:]
    def insertRandomChar(self, s):
        idx = randint(0, len(s))
        return s[:idx] + chr(randint(0, 127)) + s[idx:]
    
    

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

# JSON Fuzzer
class JSON_Fuzz(Fuzz):
    def __init__(self, seed):
        super().__init__(seed)
        self.bad_input = {
            'buffer_overflow': 'A'*999,
            'format': '%p',
            'pos': 1,
            'neg': -1,
            'zero': 0,
            'big_neg': -1111111111111111111111111111111111111111111,
            'big_pos': 1111111111111111111111111111111111111111111
        } 
        self.basic_checks = self.bad_input  # this is mutable
        self.checked_strings_set = set()
        
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
    
    '''
        Add token to the json object
    '''
    def addToken(self, mutation):
        randomToken = chr(randint(0, 127))
        whichType = randint(0, 2)
        if whichType == 0:
            # int
            mutation[randomToken] = randint()
        elif whichType == 1:
            # string
            mutation[randomToken] = self.mutateString('')
        else:
            # list
            pass
        
        return mutation
    

    
    '''
        Remove tokens from the object
    '''
    def removeToken(self, ):
        pass
    
    def mutateString(self, s):
        methods = [
            self.deleteRandomChar,
            self.insertRandomChar,
            self.flipRandomBit,
            self.multipleStringMutations
        ]
        method = choice(methods)
        return method(s)
    
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
    
    def isJson(self, mutation):
        try:
            return json.dumps(mutation)
        except:
            return None
            
    def fuzz(self):
        mutation = self.mutate()
        mutationJSON = self.isJson(mutation)
        if (mutationJSON and (mutationJSON not in self.checked_strings_set)):
            self.checked_strings_set.add(mutationJSON)
            return mutationJSON
        else:
            return self.fuzz()

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
    
def getType(filename) -> Fuzz or None:    
    print("getType() - seed: ", filename)
    
    fuzzer = Fuzz
    type, inputTxt = checkType(filename)
    
    if type == TYPE_FAIL:
        return None
    elif type == TYPE_CSV:
        print("getType() - Detected CSV")
        fuzzer = CSV_Fuzz(inputTxt)
    elif type == TYPE_JSON:
        print("getType() - Detected JSON")
        fuzzer = JSON_Fuzz(inputTxt)
    elif type == TYPE_XML:
        print("getType() - Detected XML")
        XML_Fuzz.fuzz(inputTxt)
    elif type == TYPE_PLAINTEXT:
        print("getType() - Detected Plaintext")
        Plaintext_Fuzz.fuzz(inputTxt)
    elif type == TYPE_JPG:
        print("getType() - Detected JPG")
        JPG_Fuzz.fuzz(inputTxt)
    return fuzzer

if __name__ == '__main__':
    fuzzer = getType(sys.argv[1])
    
    
    
    for i in range(10):
        # print(fuzzer.generateOverflowedInt())
        print(fuzzer.generateString())
        # print(fuzzer.fuzz())
            
    
    # if type == TYPE_FAIL:
    #     print("Failed to open file/detect input type")
    # elif type == TYPE_CSV:
    #     print("Detected CSV")
    #     CSV_Fuzz.fuzz()
    # elif type == TYPE_JSON:
    #     print("Detected JSON")
    #     JSON_Fuzz.fuzz()
    # elif type == TYPE_XML:
    #     print("Detected XML")
    #     XML_Fuzz.fuzz()
    # elif type == TYPE_PLAINTEXT:
    #     print("Detected Plaintext")
    #     Plaintext_Fuzz.fuzz()
    # elif type == TYPE_JPG:
    #     print("Detected JPG")
    #     JPG_Fuzz.fuzz()
        
    

