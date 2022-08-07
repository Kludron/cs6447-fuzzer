    def workinprogress(self) -> None:
        while self.thread.alive:

            
            if response:
                try:
                    recopy = response 
                    response = response[-1]
                    message = response['message']
                except (TypeError, KeyError, IndexError) as e:

                    break
            else:

                response = self.__write('continue')
                continue                 #SB added
            # print(message)
            # Check if persistent breakpoint is hit, or program has exited
            if message == 'stopped':
                #print(f'{self.thread}: message == stopped')
                #pprint(recopy)
                try:
                    output = response['payload']
                    reason = output['reason']
                except (KeyError) as e:
                    break
                # print(reason)
                # Check if persistent breakpoint is hit
                if reason == 'breakpoint-hit': 
                    #print('reason == breakpoint-hit')
                    cpID = time.time()

                    # Check if breakpoint was at an input function
                    try:
                        if response["payload"]["frame"]["addr"] in self.input_bpoints:   
                            # Create a checkpoint at this input function
                            self.__checkpointCreate(cpID)
                    except (KeyError, TypeError):
                        pass
                    finally:
                        # Store the path
                        response = self.gdb.write(f'backtrace {cpID}')
                
                # Check if the program exited normally
                elif reason == 'exited-normally':
                    #print(f'{self.thread}: reason == exited-normally')
                    print(f'{self.thread}: Under normal operations we should not get here') 
                    #response = self.__write('info breakpoints')
                    #pprint(f'{self.thread}:\n{response}')
                    break

                ###### [TODO] What about if the program crashes?
                else:
                    #print(f'{self.thread}: message == else')
                    try:
                        #print()
                        reason = output['reason']
                        signal = output['signal-name']
                        if reason == 'signal-received' and signal != "SIGINT":  #SB updato exclude SIGINT other all return
                            #pprint(f'---------------------------------------------')
                            print(f'{self.thread}: signal-recieved')
                            print(f'{self.thread}: {payload}')
                            print(f'{self.thread}: {output["signal-name"]}')
                            #pprint(f'---------------------------------------------')
                            return (payload, output['signal-name'])

                    except (KeyError):
                        print("="*20 + "Unhandled" + "="*20)
                        print(reason)
                        print(output)
                        # print(response)
                        # print(payload)
                    finally:
                        break

            # Check if temporary breakpoint is hit
            elif message == 'breakpoint-deleted':
                #print(f'{self.thread}: message == breakpoint-deleted')
                #pprint(f'{self.thread}:\n{recopy}')
                # print(f'Hit function for first time, deleting a temporary breakpoint')
                cpID = time.time()
                response = self.gdb.write(f'backtrace {cpID}')

            # Check if previous execute command is completed and returning  
            elif message == 'done':
                #print(f'{self.thread}: message == done')
                #pprint(f'{self.thread}:\n{recopy}')
                try:
                    if 'backtrace' in recopy[0]["payload"]:             #SB updated this response was overwritten and this was broken as a resulr\t
                        #print(f'{self.thread}: parsing backtrace results')
                        #pprint(f'{self.thread}:\n{response}')
                        self.__doBacktrace(response)
                except (TypeError, KeyError):
                    pass
                finally:
                    response = self.__write('continue')

            # Check if the program is waiting for input
            elif message == 'running':
                #print(f'{self.thread}: message == running' )
                #pprint(f'{self.thread}:\n{recopy}')
                # payload = self.fuzzer.fuzz()
                payload = self.queue.get(timeout=0.2)
                #print(f'{self.thread}: payload: {payload}')
                # self.semaphore.acquire()
                # print(self.counter)
                # self.counter += 1
                # self.semaphore.release()
                # print(payload)
                # payload = 'header,must,stay,intact\n'
                # payload += 'a,a,a,a\n' * 120  
                self.c_semaphore.acquire()      #SB this temporarily to test with known bad text
                self.counter += 1
                self.c_semaphore.release()
                # if self.counter == 20:
                #     response = self.__write(self.BAD)
                # else:
                #     response = self.__write(f'{payload}')
                
                #response = self.__write(f'{payload}')
                #pprint(f'{self.thread}:{response}')
            elif message == 'breakpoint-modified':
                #print(f'{self.thread}: message == breakpoint-modified' )
                #pprint(f'{self.thread}:\n{recopy}')
                response = self.__write('continue')

            else:
            #    print(f'{self.thread}: else -> self.__setResumeOnExit')        #SB Commented these out as I think __setResumeOnExit only need to be run before loop        
            #    self.__setResumeOnExit
                #pprint(f'{self.thread}: else')
                #pprint(f'{self.thread}:\n{recopy}')
                pass  #SB may need to remove this else or otherwise populate with other requirements
        if self.thread.alive:
            return payload, response
        else:
            return None




    def setup(self) -> None:
        # Get all functions
        func_info = self.__getConsole(self.gdb.write('info functions'))
        functions = self.__getFunctions(func_info, specifier=self.__isGoodFunction)
        
        # Get all input functions
        input_funcs = self.__getFunctions(func_info, specifier=self.__isInputFunction)
        
        # Set persistent breakpoints at input functions
        if len(input_funcs) < 1:
            # Binary does not have any input functions
            # raise Exception("Could not detect any input functions")
            print("Could not detect any input functions")
        else:
            self.input_bpoints = self.__makeBreakpoints(input_funcs, self.input_bpoints, bktype='tbreak') #SB Update to tbreak
        #pprint(self.input_bpoints)
        #pprint(f'---------------------------------------------')


        # Set temporary breakpoints at all functions
        if len(functions) < 1:
            raise Exception("Could not detect any functions")
            # print("Could not detect any functions")
        else:
            self.func_bpoints = self.__makeBreakpoints(functions, self.func_bpoints, bktype='tbreak') 
        #pprint(self.func_bpoints)
        #pprint(f'---------------------------------------------')
        
        
        
        
        
    
        # print("Breakpoints: ", len(self.func_bpoints) + len(self.input_bpoints))

        # Create breakpoint at _exit
        response = self.__write('start')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        self.__setResumeOnExit('*&_exit')
        #response = self.__write('b *&_exit')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        response = self.__write('info breakpoints')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        # Continue after start
        response = self.__write('continue')
        #pprint(response)
        #pprint(f'---------------------------------------------')
        # Set the default payload
        payload = ""

    #def start(self) -> None:

    ##############################
    #
    #        Helper functions
    #
    ##############################

    ###################
    #   Parse input
    ###################