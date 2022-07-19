
"""
Generator that makes:
    - Obscure values in the inputs (e.g. 5,U,z,Q) [__generate_random()]
    - Long inputs (e.g. aaaaaaaaaaa,b,c,d) [__generate_long]
    - Large number of values in input (e.g. a,b,c,d,e,f,g,h,i,j,k,l) [__generate_lots]
    - Large quantity of inputs (e.g. a,b,c,d\na,b,c,d\na,b,c,d) [__generate_lines]
"""

import random
import string


class CSV_Fuzzer():
    
    def __init__(self, structure) -> None:
        self.mutations = list()
        self.DELIMITER = ','
        self.maxsize = 10000
        self.structure = structure
        self.sItems = len(structure.split(self.DELIMITER))
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

    def fuzz(self):
        try:
            return self.structure + '\n' + self.mutations.pop(0)
        except IndexError:
            self.__generate()
            return self.fuzz()

if __name__ == '__main__':
    c = CSV_Fuzzer('header,must,stay,intact')
    for i in range(100):
        print(c.fuzz())
