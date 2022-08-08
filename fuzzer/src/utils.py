# Utilities for COMP6447 Fuzzer
from ctypes import sizeof
import random
import string
import sys
import json
import math
from tkinter import E
import xml.etree.ElementTree as ET
# from pwn import *
import copy
from random import choice, randint, uniform

TYPE_FAIL = -1
TYPE_CSV = 0
TYPE_JSON = 1
TYPE_JPG = 2
TYPE_XML = 3
TYPE_PLAINTEXT = 4

BYTE_MASK = 0xff

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
    # if harness detects grater code coverage from a mutation, update the seed
    # this could potentially speed up the fuzzing process by order of magnitude
    def updateSeed(self, new):
        self.seed = new;
    
    
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
        Arithmetic operations
        Theoretically does not discover significant number of execution paths.
        Probability of calling them should decrease as fuzzer runs.
    '''
    def negative(self, data):
        return -data    
    def increment(self, data):
        return data + 1
    def decrement(self, data):
        return data - 1
    def addInt(self, data):
        return data + 1234
    def minusInt(self, data):
        return data - 1234
    def addFloat(self, data):
        return data + uniform(0, 1000)
    def minusFloat(self, data):
        return data - uniform(0, 1000)
    
    
    '''
        Known Ints
    '''
    def zero(self):
        return 0
    def knownNeg(self):
        return -1
    def knownLargePosInt(self):
        return 999999
    def knownLargeNegInt(self):
        return -999999
    def knownPosFloat(self):
        return 1.5
    def knownNegFloat(self):
        return -1.5
    def intOverflow(self):
        return 9999999999999999999
    def intUnderflow(self):
        return -9999999999999999999
    def intMax(self):
        return 0x7FFFFFFF
    def intMin(self):
        return 0x80000000
    
    '''
        Magic bytes which often cause errors
    '''
    def mutate_magic(self, data):
        # tuple = (byte-size of value, value)
        values = [
            (1, 0xff),
            (1, 0x7f),
            (1, 0),
            (2, 0xffff),
            (2, 0),
            (4, 0xffffffff),
            (4, 0),
            (4, 0x80000000),
            (4, 0x40000000),
	        (4, 0x7fffffff)
        ]
        length = len(data) - 8  # make sure we dont write over the EOI marker
        idx = randint(0, length)
        n_size, n = choice(values)
        data[idx:idx + n_size] = bytearray(n)
        
    '''
        Boolean
    '''
    def setTrue(self):
        return True
    def setFalse(self):
        return False
    def flipBool(self, val):
        return not val
    
    '''
        Null
    '''
    def setNull(self):
        return None
    
    
    '''
        Random String mutators
    '''
    def flipRandomBit(self, s):
        if s == '':
            return s
        flip_array = [1,2,4,8,16,32,64,128] # possible bit masks
        idx = randint(0, len(s) - 1)
        c = s[idx]
        mask = random.choice(flip_array)
        flipped = chr(ord(c) ^ mask)    # xor the random character and bitmask
        return s[:idx] + flipped + s[idx + 1:]
    def flipRatioBits(self, s, ratio): 
        # flips a ratio of bits. Bits which have been flipped will not be flipped again
        # ratio = (0, 1]. ratio = 0.1 --> flip 10% of bits
        if s == '':
            return s
        mutation = s
        number_of_flips = len(s) * ratio
        flip_array = [1,2,4,8,16,32,64,128] # possible bit masks
        flips = []
        while len(flips) < number_of_flips:
            idx = randint(0, len(s) - 1)
            mask = random.choice(flip_array)
            flip = (idx, mask)
            if flip in flips:
                continue
            else:
                flips.append(flips)
                mutation[idx] = mutation[idx]^mask
        return mutation
    def deleteRandomChar(self, s):
        if s == '':
            return s
        idx = randint(0, len(s) - 1)
        return s[:idx] + s[idx + 1:]
    def insertRandomChar(self, s):
        idx = randint(0, len(s))
        return s[:idx] + chr(randint(0, 127)) + s[idx:]

       
    
    '''
        Byte object mutator. Given byte array, flip bits in a random byte
        Bit flipping is insignificant compared to byte flipping when it comes to discovering new execution paths, 
        so don't bother implementing some byte-flipping techniques for bit-flipping
    '''
    # given a bytearray, flip a random bit in a random byte
    # just realised that this is pretty much the same as string bit flip
    def flipRandomBitInByte(self, data):
        if data == '':
            return data
        flip_array = [1,2,4,8,16,32,64,128]
        idx = randint(0, len(data) - 1)
        mask = random.choice(flip_array)
        data[idx] = data[idx] ^ mask
        return data
    '''
        Normally used as a last resort.
        Given two input sets that differ in at least two locations, 
        splice them at a random location in the middle
        theoretically, higher variance between data samples should result in greater likelihood of execution path discovery
    '''
    def testCaseSplicing(self, data1, data2):
        mid1 = len(data1 - 1)
        mid2 = len(data2 - 1)
        idx1 = mid1 + math.round(randint(0, mid1)*uniform(-0.35, 0.35))    # try to pick a random position about the midpt
        idx2 = mid2 + math.round(randint(0, mid2)*uniform(-0.35, 0.35))
        return data1[:idx1] + data2[idx2:]
    def flipRandomByte(self, data):
        if len(data) == 0:
            return data
        mutation = data
        idx = randint(0, len(data))
        mutation[idx] = mutation[idx] ^ BYTE_MASK
        return mutation
    def flipRatioBytes(self, data, ratio):
        if len(data) == 0:
            return data
        mutation = data
        number_of_flips = len(data) * ratio
        flips = []
        while sizeof(flips) < number_of_flips:
            idx = randint(0, len(data) - 1)
            if idx in flips:
                continue
            else:
                flips.append(idx)
                mutation[idx] = mutation[idx] ^ BYTE_MASK
        return mutation
    def flipConsecutiveBytes(self, data, length):
        if len(data) == 0:
            return data
        mutation = data
        idx = randint(0, len(data) - length)    # ensures that [length] consecutive bytes WILL be flipped
        while idx < idx + length:
            mutation[idx] = mutation[idx] ^ BYTE_MASK
            idx += 1
        return mutation
    
    
    

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

# # XML Fuzzer
# class XML_Fuzz(Fuzz):
#     def __init__(self, seed):  
#         super().__init__(seed)
#     def checkType(self):
#         try:
#             ElementTree.fromstring(self.seed)
#             return True
#         except ElementTree.ParseError:
#             return False
#     def mutate():
#         pass
#     def fuzz(self):
#         # Placeholder
#         return super().fuzz()
# XML Fuzzer
class XML_Fuzz(Fuzz):
    def __init__(self, seed):
        tmp = seed.replace("\n", '')    # remove newline characters. does not affect xml validity
        super().__init__(tmp)
        # self.root = ET.fromstring(seed)
        self.initial = seed
        print("created xml fuzzer")
        # basically some known tests
        self.bad_input = {
            'zero' : str(self.zero()),
            'neg': str(self.knownNeg()),
            'large_neg' : str(self.knownLargeNegInt()),
            'large_pos' :str(self.knownLargePosInt),
            'larger_neg': str(self.intUnderflow()),
            'larger_pos': str(self.intOverflow()),
            'int_max': str(self.intMax()),
            'int_min': str(self.intMin()),
            'randomURL': "https://aasddasfqwegqce.com",
            'fmt': '%s',
            'empty': '',
            'b1': '&apos;XoiZR',
            'b2': '&quot;XoiZR',
            'b3': '&lt;Tnn96&gt;',
            'b4': '&lt;?Tnn96 ?&gt;',
            'b5': '&lt;? Tnn96 ?&gt;',
            'b6': '&lt;% Tnn96 %&gt;',
            'b7': '&lt;%= Tnn96 %&gt;'
        }
    def updateSeed(self, new):
        self.seed = new.replace('\n', '')
    
    def checkType(self):
        try:
            ET.fromstring(self.seed)
            return True
        except ET.ParseError:
            return False
    
    
    def parseXML(self, input):  # assumes that input is valid xml
        self.root = ET.fromstring(input)     # this function gives the root element of xml tree
        print("root: ", self.root)
        for child in self.root:              # iterate through all children nodes
            child.text = "fuck"
            print(child, " tag: ", child.tag, "text: ", child.text)
            for attr in self.getAttributes(child):
                print("     >>", attr)

        for x in self.root.iter():
            print(x)
        return


    # return a list of all children of element
    def getChildren(self, elem):
        return list(elem)
    # check if element has children
    def hasChild(self, elem):
        return True if len(list(elem)) else False
    # get element attributes as tuples (key, value)
    def getAttributes(self, elem):  # returns 
        return elem.items()

    
    # only called once to try stack overflow. 
    # unfortunately doesnt cause any issues for all binaries, wasted my time
    def spamElements(self, root):
        mutation = root
        opening = f"\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n<SPAM>\n"
        closing = f"</SPAM>\n </SPAM>\n </SPAM>\n </SPAM>\n </SPAM>\n</SPAM>\n</SPAM>\n </SPAM>\n </SPAM>\n </SPAM>\n </SPAM>\n</SPAM>\n"
        new_el = opening*82 + closing*82
        add = ET.fromstring(new_el)
        mutation.insert(0,add)
        return mutation
   
    
    # get duplicate of an element, but without its children nodes
    def cloneElement(self, elem):
        # create element with same tag
        clone = ET.Element(elem.tag) 
        # copy attributes
        attrs = self.getAttributes(elem)
        for (key, val) in attrs:
            clone.set(key, val)
        # copy text
        clone.text = elem.text
        # copy tail
        clone.tail = elem.tail
        return clone
    
    
    '''
        Select (elem1, elem2) from tree; elem1 is the parent and elem2 is the child
        child is recursively added to itself to create a tree
        then add the tree to the parent
    '''
    def spamElementDepth(self, tree):
        elements = self.getChildren(tree)
        elem1 = choice(elements)
        elements.remove(elem1)
        elem2 = choice(elements)
        # print("e1: ", elem1)
        # print("e2: ", elem2)
        
        root = child = elem2
        for i in range(randint(1, 20)):        # no point going too deep
            root = self.cloneElement(child)     # create clone
            root.append(child)                  # append clone to root
            child = root                        # set child as root
        
        mutation = tree
        for elem in mutation:
            if elem.tag == elem1.tag:
                elem.append(root)
        return mutation


    '''
        Select (elem1, elem2) from tree; elem1 is the parent and elem2 is the child
        child is added to parent multiple times
    '''
    def spamElementBreadth(self, tree):
        elements = self.getChildren(tree)
        elem1 = choice(elements)
        elements.remove(elem1)
        elem2 = choice(elements)
        # print("e1: ", elem1)
        # print("e2: ", elem2)
        
        mutation = tree
        for elem in mutation:
            if elem.tag == elem1.tag:
                clone = self.cloneElement(elem2)
                for i in range(randint(1, 20)): 
                    elem.append(clone)
        return tree 

    '''
        Restructuring of elements
        - add/remove/replace/duplicate/shuffle content(s) in element
        - add contents from one element to another
        - move contents from one element to another
    '''
    def chromosomeRecombination(self, tree):
        mutation = tree
        strategy = randint(0, 6)
        if strategy == 0:
            # copy children from one to another
            l2_elems = self.levelTwoElements(tree)
            parent, child = choice(l2_elems)
            l1_elems = self.levelOneElements(tree)
            l1_elems.remove(parent)
            dest = choice(l1_elems)
            # print("C-0")
            # print("pair: ", parent, child)
            # print("dst: ", dest)
            count = 0
            for elem in mutation.iter():
                if elem == dest:
                    try:
                        dest.append(child)
                        break
                    except:
                        continue
        if strategy == 1:
            # remove elements
            # print("C-1")
            l1_elems = self.levelOneElements(tree)
            target = choice(l1_elems)
            # print("remove: ", target)
            mutation.remove(target)
        if strategy == 2:
            # duplicate contents
            # print("C-2")
            l2_elems = self.levelTwoElements(tree)
            parent, _ = choice(l2_elems)
            # print("Parent: ", parent)
            children = self.getChildren(parent)
            for elem in mutation.iter():
                if elem == parent:
                    try:
                        for child in children:
                            parent.append(child)
                        break
                    except:
                        continue
        if strategy == 3:
            # fuzz text of random element based on bad input or random string
            # print("C-3")
            if randint(0,1) == 0:
                elements = self.levelOneElements(tree)
                target = choice(elements)
                avoid = ['root', 'html', 'body', 'head', 'tail', 'link', 'div']
                if target.tag not in avoid:
                    if randint(0, 1) == 0:
                        text = choice(list(self.bad_input.values()))
                    else:
                        text = self.generateString()
                    target.text = text
            else:
                elements = self.levelTwoElements(tree)
                parent, target = choice(elements)
                avoid = ['root', 'html', 'body', 'head', 'tail', 'link', 'div']
                if target.tag not in avoid:
                    
                    if randint(0, 1) == 0:
                        text = choice(list(self.bad_input.values()))
                    else:
                        text = self.generateString()
                    target.text = text
                # print("target: ", target)
                # print("text: ", text)
        if strategy == 4:
            # fuzz the attribute value of random element
            # print("C-4")
            if randint(0,1) == 0:
                elements = self.levelOneElements(tree)
                target = choice(elements)
                attributes = target.items()
                for attr in attributes:
                    newAttr = choice(list(self.bad_input.values()))
                    target.set(attr[0], newAttr)
            else:
                elements = self.levelTwoElements(tree)
                parent, target = choice(elements)
                attributes = target.items()
                for attr in attributes:
                    newAttr = choice(list(self.bad_input.values()))
                    target.set(attr[0], newAttr)
        if strategy == 5:
            # add attribute to random element
            # print("C-5")
            elements = self.levelOneElements(tree)
            target = choice(elements)
            attributes = target.items()
            for attr in attributes:
                if randint(0, 1) == 0:
                    key = choice(list(self.bad_input.values()))
                else:
                    key = self.generateString()
                if randint(0, 1) == 0:
                    val = choice(list(self.bad_input.values()))
                else:
                    val = self.generateString()   
                target.set(key, val)
        if strategy == 6:
            # insert bad elements?
            # print("C-6")
            bad = [
                '<div class="no_add" id="yes"><a class="no_add" href="http://google.com">Here is some link...</a><link class="no_add" href="http://somewebsite.com" /><span class="no_add">text</span></div>',
                '<span class="no_add" id="wot">fuzz me</span>',
                '<format_string class="no_add">%s</format_string>',
                '<trivial class="no_add" id="trivial">trivial</trivial>',
                '<div class="no_add" id="fuzz_me" data="fuzz_me" name="fuzz_me"></div>'
            ]
            elemstr = choice(bad)
            # print(elemstr)
            new = ET.fromstring(elemstr)
            elements = list(elem for elem in mutation.iter())
            target = choice(elements)
            target.append(new)
        return mutation


    '''
        Restructuring of element heirarchy
        - child go up one level
        - child swap with parent
    '''
    def heirarchialRecombination(self, tree):
        mutation = tree
        l2_elems = self.levelTwoElements(tree)
        strategy = randint(1, 1)
        if strategy == 0:
            # print('H-0')
            parent, child = choice(l2_elems)
            for elem in mutation.iter():
                if elem == parent:
                    try:
                        parent.remove(child)
                        break
                    except:
                        continue
            mutation.append(child)
        if strategy == 1:
            # print("H-1")
            parent, child = choice(l2_elems)
            pos = -1
            count = 0
            for elem in mutation.iter():
                if elem == parent:
                    try:
                        parent.remove(child)
                        mutation.remove(parent)
                        pos = count
                        break
                    except:
                        continue
                count += 1
            child.append(parent)
            mutation.insert(pos-1, child)     # insert the new child node to where the old parent node used to be
        return mutation # can't believe this works

    
    '''
        Get elements
    '''
    def levelOneElements(self, root):
        return self.getChildren(root)
    '''
        Get single nested elements
        returns tuple (parent, child)
    '''
    def levelTwoElements(self, root):
        elements = []
        for elem in self.getChildren(root):
            for child in self.getChildren(elem):
                elements.append((elem, child))
        return elements 
    
    
    def mutate(self):
        xml = ET.fromstring(self.seed)
        mutation = self.seed
        
        # repetitions = randint(1, 10)
        # for round in range(repetitions):
        #     strategy = randint(0, 3)
        #     print(strategy)
        #     if strategy == 0:
        #         xml = self.spamElementDepth(xml)
        #     elif strategy == 1:
        #         xml = self.spamElementBreadth(xml)
        #     elif strategy == 2:
        #         xml = self.chromosomeRecombination(xml)
        #     elif strategy == 3:
        #         xml = self.heirarchialRecombination(xml)

        strategy = randint(0, 3)
        if strategy == 0:
            xml = self.spamElementDepth(xml)
        elif strategy == 1:
            xml = self.spamElementBreadth(xml)
        elif strategy == 2:
            xml = self.chromosomeRecombination(xml)
        elif strategy == 3:
            xml = self.heirarchialRecombination(xml)
        mutation = ET.tostring(xml, encoding='unicode', method='xml')
        return mutation
    
    def fuzz(self):
        return self.mutate()

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
        print("created jpg fuzzer")
    # I'm guessing we need to use bit flipping for this one
    def mutate(self):
        strategy = randint(0, 100)
        if strategy < 20:
            mutation = self.mutate_magic(self.seed)
        elif strategy < 30:
            ratio = uniform(0.00001, 0.001)
            mutation = self.flipRatioBits(self.seed, ratio)
        elif strategy <  65:
            mutation = self.flipRandomBit(self.seed)
        elif strategy < 98:
            mutation = self.flipRandomByte(self.seed)
        elif strategy <= 100:
             # this method has higher probability of corrupting the jpg file format, we don't want to use it too often
            ratio = uniform(0.00001, 0.0001)
            mutation = self.flipRatioBytes(self.seed, ratio)
        return mutation
        # return self.seed
    
    # replace with magic byte
    def mutate_magic(self, data):
        # tuple = (byte-size of value, value)
        values = [
            (1, 0xff),
            (1, 0x7f),
            (1, 0),
            (2, 0xffff),
            (2, 0),
            (4, 0xffffffff),
            (4, 0),
            (4, 0x80000000),
            (4, 0x40000000),
            (4, 0x7fffffff)
        ]
        length = len(data) - 8  # make sure we dont write over the EOI marker
        idx = randint(0, length)
        n_size, n = choice(values)
        print("magic mutate: ", idx, hex(n), n_size)
        # data[idx:idx + n_size] = bytearray(n)
        # return data
        if n_size == 1:
            if n == 0xff:			# 0xFF
                data[idx] = 0xff
            elif n == 0x7f:		# 0x7F
                data[idx] = 0x7f
            elif n == 0:			# 0x00
                data[idx] = 0
        elif n_size == 2:
            if n == 0xffff:			# 0xFFFF
                data[idx] = 0xff
                data[idx + 1] = 0xff
            elif n == 0:			# 0x0000
                data[idx] = 0
                data[idx + 1] = 0
        elif n_size == 4:
            if n == 0xFFFFFFFF:			# 0xFFFFFFFF
                data[idx] = 0xff
                data[idx + 1] = 0xff
                data[idx + 2] = 0xff
                data[idx + 3] = 0xff
            elif n == 0:			# 0x00000000
                data[idx] = 0
                data[idx + 1] = 0
                data[idx + 2] = 0
                data[idx + 3] = 0
            elif n == 0x80000000:		# 0x80000000
                data[idx] = 0x80
                data[idx + 1] = 0
                data[idx + 2] = 0
                data[idx + 3] = 0
            elif n == 0x40000000:			# 0x40000000
                data[idx] = 0x40
                data[idx + 1] = 0
                data[idx + 2] = 0
                data[idx + 3] = 0
            elif n == 0x7FFFFFFF:		# 0x7FFFFFFF
                data[idx] = 0x7f
                data[idx + 1] = 0xff
                data[idx + 2] = 0xff
                data[idx + 3] = 0xff
        return data
      
    # randomly flip a proportion of bits
    def flipRatioBits(self, data, ratio):
        length = len(data) - 4 #jpg file format requires SOI and EOI which are the first 2 and last 2 bytes. We don't want to touch them
        num_of_flips = int(length * ratio)
        print("flip bits ratio: ", ratio, num_of_flips)
        indexes = []
        flip_array = [1,2,4,8,16,32,64,128]
        while len(indexes) < num_of_flips:
            indexes.append(randint(0, length))
        for x in indexes:
            mask = random.choice(flip_array)
            data[x] = data[x] ^ mask
        return data
    
    def flipRandomBit(self, data):
        print("flip single bit")
        length = len(data) - 4 #jpg file format requires SOI and EOI which are the first 2 and last 2 bytes. We don't want to touch them
        idx = randint(0, length)
        flip_array = [1,2,4,8,16,32,64,128]
        mask = random.choice(flip_array)
        data[idx] = data[idx] ^ mask
        return data
    def flipRandomByte(self, data):
        print("flip single byte")
        length = len(data) - 4 #jpg file format requires SOI and EOI which are the first 2 and last 2 bytes. We don't want to touch them
        idx = randint(0, length)
        data[idx] = data[idx] ^ 0xff
        return data
    def flipRatioBytes(self, data, ratio):
        length = len(data) - 4 #jpg file format requires SOI and EOI which are the first 2 and last 2 bytes. We don't want to touch them
        num_of_flips = int(length * ratio)
        print("flip ratio bytes", ratio*100, num_of_flips)
        indexes = set()
        while len(indexes) < num_of_flips:
            indexes.add(randint(0, length))
        for idx in indexes:
            data[idx] = data[idx] ^ 0xff
        return data
            
        
    def fuzz(self):
        return self.mutate()

'''
    returns (fileType, seed)
    jpg type requires reading the file as a bytearray
'''
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
        f = open(filename, "rb").read()
        fileBytes = bytearray(f)
        return TYPE_JPG, fileBytes


'''
    From seed file, detect type and return type-specific fuzzer object
'''
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
        fuzzer = XML_Fuzz(inputTxt)
    elif type == TYPE_PLAINTEXT:
        print("getType() - Detected Plaintext")
        # Plaintext_Fuzz.fuzz(inputTxt)
    elif type == TYPE_JPG:
        print("getType() - Detected JPG")
        fuzzer = JPG_Fuzz(inputTxt)
    return fuzzer

if __name__ == '__main__':
    fuzzer = getType(sys.argv[1])
    mutation = fuzzer.mutate()
    print(mutation)
    
    f = open("tests/mutated.txt", "w")
    f.write(mutation)
    f.close()
    
    # for i in range(10):
    #     print(fuzzer.generateOverflowedInt())
    #     print(fuzzer.generateString())
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
        
    

