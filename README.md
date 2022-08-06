# COMP6447 Fuzzer

Project Spec: https://webcms3.cse.unsw.edu.au/COMP6447/22T2/resources/75130

Google Docs (Report Documentation): 

[Midterm Report](https://docs.google.com/document/d/1dvWuJvmvnArauf43ZDLuO7kDrXm9PjhW4JgYlKKciDs/edit?usp=sharing)

[Final Report](https://docs.google.com/document/d/1MyWc96-o0q8fuBDCFl_NAeyxPlJ0eCIVOhi8xBs3S7Q/edit?usp=sharing)

Binaries Download: https://cloudstor.aarnet.edu.au/plus/s/QnDputxJslGQok8

## Key Dates:

Midpoint submission:
    17:59 Sunday July 17 (end of Week 7, Sydney time)

Final submission:
    17:59 Sunday August 7 (end of Week 10, Sydney time)

## Important notes:

Do not test or run the fuzzer on CSE systems.

## Project Plan
### Description

You are to work in a team and write a fuzzer to look for vulnerabilities. There is intentionally a wide scope to this assignment and a lot of freedom for you to decide on your fuzzer capabilities. We will be providing support in course forums and have weekly check-ins to ensure you are staying on task.

The link to the binaries is here: https://cloudstor.aarnet.edu.au/plus/s/QnDputxJslGQok8

We will be testing all the fuzzers against these binaries.
This assessment is worth 20% of your final mark.

Register your group here: https://forms.gle/2VkyJ4euXdjtoZAYA If you are not in a group by the end of week 6 talk to your tutor!

## Fuzzer (30 Marks)
"Fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. The program is then monitored for exceptions such as crashes, failing built-in code assertions, or potential memory leaks. This structure is specified, e.g., in a file format or protocol and distinguishes valid from invalid input. An effective fuzzer generates semi-valid inputs that are "valid enough" in that they are not directly rejected by the parser, but do create unexpected behaviors deeper in the program and are "invalid enough" to expose corner cases that have not been properly dealt with." ~wikipedia

For this project you will be required to implement a black box fuzzer, that given a binary containing a single vulnerability and a file containing one valid input to the binary, will need to find a valid input that causes an incorrect program state to occur (crash, invalid memory write, heap UAF, etc).

All binaries will read in from stdin.

The main goal of your fuzzer should be to touch as many codepaths as possible within the binary by either mutating the supplied valid input or generating completely new input (empty files, null bytes, really big files, etc).

Attempts to make a trivial fuzzer that simply return results from manual source code auditing or relies extensively on other tooling will be considered as not completing the assignment . This will receive a 0 grade .

You are permitted to do anything you wish (other than the above) to achieve the following functionality .

The only real requirement is that you supply an executable file that takes in two arguments (a sample input and the binary to fuzz), your executable should create a file called bad.txt which if passed into the binary as input causes the program to crash. Your fuzzer can add more files, or print debugging data to stdout as you wish. If you wish to create more files for processing, we recommend using the /tmp directory.

```
$ ls
fuzzer binaryinput.txt binary
$ ./fuzzer binary binaryinput.txt
Fuzzing this thing...
Found bad input.
$ ls
fuzzer binary bad.txt binaryinput.txt
$ cat bad.txt | binary
Segmentation Fault
```

The marks breakdown for the fuzzer is as follows ( / 30 marks)

- 10 marks - General Fuzzer
    - Finding all vulnerabilities in the 11 provided binaries.
    - Writing test vulnerable binaries to test your fuzzer
- 10 marks - Fuzzer Functionality
    - Mutation Strategies
        - Basic (bit flips, byte flips, known ints)
        - Intermediate (repeated parts, keyword extraction, arithmetic)
        - Advanced (coverage based mutations)
    - Understanding and manipulation of file formats (Manipulating file headers, field names, data structures, etc)
        - Basic (JSON, CSV, XML)
        - Intermediate (JPEG, ELF)
        - Advanced (PDF)
- 10 marks - Harness Functionality
    - Detecting the type of crash (2 marks)
    - Detecting Code Coverage (2 marks)
    - Avoiding overheads (2 marks)
        - Not creating files
        - In memory resetting (Not calling execve)
    - Useful logging / statistics collection and display (2 marks)
    - Detecting Hangs / Infinite loops (2 marks)
        - Detecting infinite loop (code coverage) vs slow running program (timeout approach)
- Bonus (6 marks) - Something awesome
    - Something cool your fuzzer does (consult course staff to see if your thing is valid).
    - Finding novel / non-trivial bugs in Public Software / OSS Software with your fuzzer.

Partial marks will be rewarded at the discretion of the marker if you miss some vulnerabilities.

## Installation 

You can optionally provide an install . sh script in your tar file, this will be run before your fuzzer is tested. This can be used to libraries you may need from apt-get or pip or somewhere else, and setup the environment for your testing.

The time this install script takes to run won't count towards the 180s limit for your fuzzer.

### Assumptions

You can assume these facts when developing your fuzzer.

1. All binaries will have a vulnerability.
2. All binaries will function normally (return 0, not crash, no errors) when the relevant input.txt is passed into them.
3. All binaries will expect input in one of the following formats:
    1. Plaintext (multiline)
    2. JSON
    3. XML
    4. CSV
    5. JPEG
    6. ELF
    7. PDF
4. The input. txt provided will be a valid form of one of these text formats.
5. Your fuzzer will have a maximum of 180 seconds per binary to find a vulnerability. If your program doesn't create a file and exit by this time, it won't count as a solution.
6. All binaries will be 32 bit linux ELF's (except xml3).
7. All vulnerabilities will result in memory corruption.

### Technologies available
You can assume your programs will be run on an up to date 64-bit Linux system. The system will have the following programs installed:

- python
    - pwntools
- gdb
- gcc
    - C libraries

If you have a strong case to another required library / tool being available, please email the course staff and we can discuss adding it.

### Hints
Some hints if you are stuck on where to start.

- Try sending some known sample inputs (nothing, certain numbers, certain strings, etc)
- Try parsing the format of the input (normal text, json, etc) and send correctly formatted data with fuzzed fields.
- Try manipulating the sample input (bit flips, number replacement, etc)
- Try something awesome :D (There are no right answers)

### Something Awesome

The Something Awesome section is totally optional, and a bonus to the assignment. If you have something really cool you'd like to add to your fuzzer, let us know. The bonus marks are totally up to the discretion of the marker. This section is intentionally vague, we want you to think of cool ideas to add to your fuzzer.

**You cannot get more than 100% in this assignment.** The bonus 6 marks will count only for this assignment. If you get full marks, you don't get any bonus marks.

## Documentation

Your fuzzer design and functionality (around 1-2 pages)

This section should explain, in a readable manner:

- How your fuzzer works
    - Describe both in detail the different mutation strategies you use, as well as the Harness's capabilities
- What kinds of bugs your fuzzer can find
- What improvements can be made to your fuzzer (Be honest. We won't dock marks for things you didn't implement. This shows reflection and understanding)
- If you attempt any bonus marks - How your fuzzer achieves these bonus marks.
- **It is insufficient if the document merely states "our fuzzer injects random values and finds bugs". We want details that show deep understanding.**

You do not have to follow any format, but this is the kind of information we expect to see in your documentation.

## Assignment Check-In (10 Marks)

We want you to start early, so you don't get stressed last minute trying to implement your fuzzer. In week 7, you will need to submit a basic working version of your fuzzer and a half page description of your fuzzer, similar to the documentation description above. It does not have to the complete functionality of your fuzzer, but we want to make sure that you've started work on the major project.

For the check-in, we will only test your fuzzer against two binaries ( `csv1, json1` ). Like the final submission, we will supply a sample input so your fuzzer can manipulate our input.

We will run `./fuzzer program sampleinput.txt` to test your fuzzer.

The marks breakdown the midpoint check-in is:

- (6 marks) Find a vulnerability in the `csv1 and json1` binaries.
- (4 marks) Half page description of your fuzzer functionality so far and the fuzzer design [ ***writeup.md*** ].

Attempts to make a trivial fuzzer that simply return results from manual source code auditing or **relies extensively on other tooling** will be considered as **not completing the assignment**. **This will receive a 0 grade**.

## Submission
There is a **5% late penalty** taken off the maximum mark you can achieve for **each day** the submission is late, **up to 5 days late**.

The midpoint submission is 17:59 Sunday July 17 (end of Week 7, Sydney time).

`give cs6447 midpoint writeup.md fuzzer.tar`

The fuzzer final submission is 17:59 Sunday August 7 (end of Week 10, Sydney time).

`give cs6447 fuzzer writeup.md fuzzer.tar`
