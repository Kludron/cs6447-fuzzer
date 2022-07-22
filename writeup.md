Fuzzer - Check-In
===========================
-------------------------------------
At this midpoint stage, our fuzzer performs the following main steps:

 * Perform analysis of the seed file to identify its type in order to invoke the correct fuzzing engine.
 * Initialize the harness and the main queue which is shared between threads.
 * Spawn one fuzzer thread which generates mutations and adds these to the queue and twenty tester threads which take mutations from the queue and input these to the binary.
 * The harness then monitors the running time, test numbers, testing rate and queue length until such time that binary crashes or the fuzzer is stopped.

Depending on the type of binary file detected at runtime, the fuzzer thread invokes the relevant fuzzing engine to generate mutations specific to the binary being fuzzed. Various types of mutations are performed which include input length, integer overflows, large negative and positive numbers and deletion and insertion of random characters. These mutations are then added to the main queue. Currently there are fuzzing engines for CSV and JSON file types in the fuzzer.

The tester threads take mutations from the queue and use these as input for executions of the binary. The tester threads monitor the return value of the binary. If the binary returns an error the tester thread records the input that generated this error in the bad.txt file and indicates to the main thread that fuzzing was successful which causes all threads to be exited and the fuzzer stopped.

While mutations continue to be generated and tested against the binary, the harness gathers metrics on the fuzzer and displays these as output to the terminal. These are constantly updated.

Once either

* fuzzing was successful,
* three minutes elapses or
* CTRL + C is pressed

the fuzzer quits.

The next steps we need to focus on include

* monitor for other signs of vulnerabilities other than just segfaults such as invalid memory rights
* improving our fuzzing strategies
* adding additional fuzzing engines for the remaining file types
* determining code coverage
* improving performance

------------------

