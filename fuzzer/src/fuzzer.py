# COMP6447 Fuzzer
import copy
from secrets import choice
import sys
import json
import xml.etree.ElementTree as ElementTree
from numpy import isin, void
from pwn import *

TYPE_FAIL = -1
TYPE_CSV = 0
TYPE_JSON = 1
TYPE_JPG = 2
TYPE_XML = 3
TYPE_PLAINTEXT = 4

# Generic Fuzzer Class
class Fuzz():
    def __init__(self, input):
        self.input = input
    def checkType(self):
        return False
    def mutate(self):
        pass
    def fuzz():
        pass
        

# CSV Fuzzer
class CSV_Fuzz(Fuzz):
    def __init__(self, input):
        super().__init__(input)
    def checkType(self):
        self.lines = self.input.split("\n")
        first_row_commas = self.lines[0].count(",")
        
        for line in self.lines:
            if line.count(",") != first_row_commas or first_row_commas == 0:
                return False
        return True
    def mutate(self):
        pass
    def fuzz():
        pass

# JSON Fuzzer
class JSON_Fuzz(Fuzz):
    def __init__(self, input):
        super().__init__(input)
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
            self.jsonObj = json.loads(self.input)
        except:
            self.jsonObj = {}
        
    def checkType(self):
        try:
            self.jsonObj = json.loads(self.input)
            print(self.jsonObj)
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
        # test for any basic errors
        if (self.basic_checks):
            mutation = self.basicMutate()
        else:
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
        return s[:idx] + chr(randint(32, 127)) + s[idx:]
    
    def flipRandomBit(self, s):
        if s == '':
            return s
        idx = randint(0, len(s) - 1)
        c = s[idx]
        mask = 1 << randint(0,6)
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
        for x in range(20):
            print(self.mutate())





# XML Fuzzer
class XML_Fuzz(Fuzz):
    def __init__(self, input):  
        super().__init__(input)
    def checkType(self):
        try:
            ElementTree.fromstring(self.input)
            return True
        except ElementTree.ParseError:
            return False
    def mutate(self):
        pass
    def fuzz():
        pass

# Plaintext Fuzzer. No need to overwrite checkType()
class Plaintext_Fuzz(Fuzz):
    def __init__(self, input):  
        super().__init__(input)
    def mutate(self):
        pass
    def fuzz():
        pass

# JPG Fuzzer. No need to overwrite checkType()
class JPG_Fuzz(Fuzz):
    def __init__(self, input):  
        super().__init__(input)
    # I'm guessing we need to use bit flipping for this one
    def mutate(self):
        pass
    def fuzz():
        pass
        

def checkType(filename):
    try:
        fp = open(filename, 'r')
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


if __name__ == '__main__':
    # print("Sample input: ", sys.argv[1])
    
    fuzzer = Fuzz
    type, inputTxt = checkType(sys.argv[1])
    
    if type == TYPE_FAIL:
        print("Failed to open file/detect input type")
        exit
    elif type == TYPE_CSV:
        print("Detected CSV")
        fuzzer = CSV_Fuzz()
    elif type == TYPE_JSON:
        # print("Detected JSON")
        fuzzer = JSON_Fuzz(inputTxt)
    elif type == TYPE_XML:
        print("Detected XML")
        XML_Fuzz.fuzz()
    elif type == TYPE_PLAINTEXT:
        print("Detected Plaintext")
        Plaintext_Fuzz.fuzz()
    elif type == TYPE_JPG:
        print("Detected JPG")
        JPG_Fuzz.fuzz()
    
    fuzzer.fuzz()
        
        
