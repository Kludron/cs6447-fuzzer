# COMP6447 Fuzzer
import sys
import json
import xml.etree.ElementTree as ElementTree
from numpy import void
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
    def mutate():
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
    def mutate():
        pass
    def fuzz():
        pass

# JSON Fuzzer
class JSON_Fuzz(Fuzz):
    def __init__(self, input):
        super().__init__(input)
        self.jsonObj = {}
    def checkType(self):
        try:
            self.jsonObj = json.loads(self.input)
            print(self.jsonObj)
            return True
        except ValueError:
            return False
    def mutate():
        # do something
        pass
    def fuzz():
        pass

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
    def mutate():
        pass
    def fuzz():
        pass

# Plaintext Fuzzer. No need to overwrite checkType()
class Plaintext_Fuzz(Fuzz):
    def __init__(self, input):  
        super().__init__(input)
    def mutate():
        pass
    def fuzz():
        pass

# JPG Fuzzer. No need to overwrite checkType()
class JPG_Fuzz(Fuzz):
    def __init__(self, input):  
        super().__init__(input)
    # I'm guessing we need to use bit flipping for this one
    def mutate():
        pass
    def fuzz():
        pass
        

def checkType(filename):
    try:
        fp = open(filename, 'r')
        inputTxt = fp.read().strip()
        
        if (JSON_Fuzz(inputTxt).checkType()):
            return TYPE_JSON
        elif (XML_Fuzz(inputTxt).checkType()):
            return TYPE_XML
        elif (CSV_Fuzz(inputTxt).checkType()):
            return TYPE_CSV
        else:
            return TYPE_PLAINTEXT
    except IOError:
        return TYPE_FAIL
    except:
        return TYPE_JPG


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
